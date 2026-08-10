"""
monitor_lifecycle.py — Monitor 进程全生命周期管理器

统一管理 Monitor 守护进程的启动、停止、任务引用计数、资源清理。
解决以下问题:
  1. 僵尸进程残留 (PID 文件死锁 → 新进程无法注册)
  2. 任务计数器泄漏 (异常路径未递减 → Monitor 永不自动关闭)
  3. 竞态条件 (多线程同时启动/停止 Monitor)
  4. 资源泄露 (FIFO/PID文件在进程退出后未清理)
  5. app.py 关闭时 Monitor 子进程未被终止

设计原则:
  - 线程安全: 所有状态变更由 threading.Lock 保护
  - 进程追踪: 记录所有由本管理器启动的 Monitor 子进程
  - 任务计数: 引用计数确保多任务共享 Monitor 时不会过早关闭
  - 优雅降级: 启动失败时自动清理残留资源，重新尝试
  - 录制/监测独立: 手动启停不受任务计数影响 (forced stop/start)

用法:
    from monitor_lifecycle import MonitorLifecycleManager
    mgr = MonitorLifecycleManager.instance()

    # 启动时清理
    mgr.startup_cleanup()

    # 任务中使用 Monitor
    with mgr.task_scope():
        mgr.start_monitor()
        # ... 执行需要 Monitor 的任务 ...

    # 手动停止 (不受任务计数限制)
    mgr.stop_monitor_forced()

    # 服务关闭
    mgr.shutdown()
"""

import os
import sys
import time
import signal
import errno
import fcntl
import threading
import subprocess
from datetime import datetime
from contextlib import contextmanager
from typing import Optional, Dict, List


# ── 路径常量 ──────────────────────────────────────────────────
def _base_dir() -> str:
    return os.path.dirname(os.path.abspath(__file__))


def _project_dir() -> str:
    return os.path.dirname(_base_dir())


def _monitoring_run_dir() -> str:
    return os.path.join(_project_dir(), ".monitoring")


def _fifo_path() -> str:
    return os.path.join(_monitoring_run_dir(), "pipe")


def _pid_file_path() -> str:
    return os.path.join(_monitoring_run_dir(), "monitor.pid")


def _output_dir() -> str:
    return os.path.join(_base_dir(), "output", "demo_monitoring")


def _monitor_script() -> str:
    return os.path.join(_base_dir(), "monitor_daemon.py")


def _records_dir() -> str:
    return os.path.join(_project_dir(), "records")


# ── MonitorLifecycleManager ───────────────────────────────────

class MonitorLifecycleManager:
    """
    Monitor 进程全生命周期管理器 (线程安全单例)。

    Attributes:
        _lock: 保护所有状态变更的互斥锁
        _task_count: 活跃任务引用计数 (Monitor 依赖者数量)
        _monitor_proc: 当前 Monitor 子进程对象 (Popen)
        _shutting_down: 服务是否正在关闭
    """

    _instance: Optional["MonitorLifecycleManager"] = None
    _instance_lock = threading.Lock()

    def __init__(self):
        self._lock = threading.RLock()
        self._task_count: int = 0
        self._monitor_proc: Optional[subprocess.Popen] = None
        self._shutting_down: bool = False
        # 追踪所有启动过的进程 (用于 shutdown 时批量终止)
        self._tracked_pids: List[int] = []

    # ── 单例 ──────────────────────────────────────────────────

    @classmethod
    def instance(cls) -> "MonitorLifecycleManager":
        """获取全局单例"""
        if cls._instance is None:
            with cls._instance_lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    @classmethod
    def reset_instance(cls):
        """重置单例 (仅用于测试)"""
        with cls._instance_lock:
            if cls._instance is not None:
                try:
                    cls._instance.shutdown()
                except Exception:
                    pass
            cls._instance = None

    # ── 启动阶段清理 ──────────────────────────────────────────

    def startup_cleanup(self) -> Dict:
        """
        系统启动时清理所有残留资源。

        执行步骤:
          1. 扫描所有名为 monitor_daemon.py 的进程，发送 SIGTERM
          2. 等待 2 秒后，对未退出的进程发送 SIGKILL
          3. 删除过期的 PID 文件
          4. 清理残留的 FIFO 管道 (如果无进程使用)

        Returns:
            dict: {"zombies_killed": int, "pid_file_cleaned": bool, "fifo_cleaned": bool}
        """
        result = {"zombies_killed": 0, "pid_file_cleaned": False, "fifo_cleaned": False}

        # 1. 查找并终止所有 monitor_daemon.py 僵尸进程
        zombies = self._find_monitor_processes()
        for pid in zombies:
            try:
                os.kill(pid, signal.SIGTERM)
                result["zombies_killed"] += 1
            except OSError:
                pass

        # 2. 等待僵尸退出
        if zombies:
            time.sleep(1.0)
            for pid in zombies:
                try:
                    os.kill(pid, 0)
                    # 仍然存活 → SIGKILL
                    os.kill(pid, signal.SIGKILL)
                except OSError:
                    pass
            time.sleep(0.5)

        # 3. 清理过期 PID 文件
        if os.path.isfile(_pid_file_path()):
            try:
                with open(_pid_file_path(), "r") as f:
                    old_pid = int(f.read().strip())
                if not self._is_pid_alive(old_pid):
                    # PID 无效或进程已是僵尸
                    try:
                        os.remove(_pid_file_path())
                        result["pid_file_cleaned"] = True
                    except OSError:
                        pass
            except (ValueError, OSError):
                try:
                    os.remove(_pid_file_path())
                    result["pid_file_cleaned"] = True
                except OSError:
                    pass

        # 4. 清理残留 FIFO (仅在无 Monitor 进程时)
        fifo = _fifo_path()
        if os.path.exists(fifo):
            remaining = self._find_monitor_processes()
            if not remaining:
                try:
                    os.remove(fifo)
                    result["fifo_cleaned"] = True
                except OSError:
                    pass

        # 5. 确保运行时目录存在
        os.makedirs(_monitoring_run_dir(), exist_ok=True)

        return result

    def _find_monitor_processes(self) -> List[int]:
        """查找所有 monitor_daemon.py 进程的 PID 列表"""
        pids = []
        try:
            # 使用 pgrep 精确匹配
            result = subprocess.run(
                ["pgrep", "-f", "monitor_daemon\\.py"],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0 and result.stdout.strip():
                for line in result.stdout.strip().split("\n"):
                    try:
                        pid = int(line.strip())
                        if pid != os.getpid():
                            pids.append(pid)
                    except ValueError:
                        pass
        except (FileNotFoundError, subprocess.TimeoutExpired):
            # pgrep 不可用 → 回退到 ps + grep
            try:
                result = subprocess.run(
                    ["ps", "-eo", "pid,args", "--no-headers"],
                    capture_output=True, text=True, timeout=5,
                )
                for line in result.stdout.split("\n"):
                    if "monitor_daemon.py" in line and "grep" not in line:
                        parts = line.strip().split(None, 1)
                        if parts:
                            try:
                                pid = int(parts[0])
                                if pid != os.getpid():
                                    pids.append(pid)
                            except ValueError:
                                pass
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass
        return pids

    # ── Monitor 启动 ──────────────────────────────────────────

    def start_monitor(self, record: bool = False) -> Optional[Dict]:
        """
        启动 Monitor 守护进程。

        幂等操作: 如果 Monitor 已在运行，直接返回状态。
        自动清理: 启动前检查并清理过期 PID 文件。

        Args:
            record: 是否启用旁路录制

        Returns:
            dict: Monitor 状态 (monitor_running, monitor_pid, fifo_path, ...)
                  或 None (启动失败)
        """
        with self._lock:
            # 快速路径: 已在运行
            status = self._check_status()
            if status["monitor_running"]:
                return status

            # 清理过期 PID 文件
            self._clean_stale_pid_file()

            # 验证 monitor_daemon.py 存在
            script = _monitor_script()
            if not os.path.isfile(script):
                return None

            # 确保目录存在
            os.makedirs(_monitoring_run_dir(), exist_ok=True)

            # 创建/重建 FIFO
            fifo = _fifo_path()
            # 如果 FIFO 存在但无 Monitor (已确认)，说明是残留，删除重建
            if os.path.exists(fifo):
                try:
                    os.remove(fifo)
                except OSError:
                    pass
            try:
                os.mkfifo(fifo)
                os.chmod(fifo, 0o666)  # 允许所有用户读写 FIFO，防止跨用户权限问题
            except OSError as e:
                if e.errno != errno.EEXIST:
                    return None

            # 构建命令
            cmd = [
                sys.executable, script,
                "--fifo", fifo,
                "--output", _output_dir(),
                "--mode", "daemon",
                "--pid-file", _pid_file_path(),
            ]
            if record:
                cmd.extend(["--record", "--record-dir", _records_dir()])

            # 启动 Monitor 子进程（stderr 重定向到日志文件以便排查问题）
            stderr_log = os.path.join(_monitoring_run_dir(), "monitor_stderr.log")
            try:
                stderr_fh = open(stderr_log, "a")
                stderr_fh.write(f"\n=== Monitor 启动 {datetime.now().isoformat()} ===\n")
                stderr_fh.flush()
                proc = subprocess.Popen(
                    cmd,
                    stdout=stderr_fh,
                    stderr=stderr_fh,
                    cwd=_base_dir(),
                )
                stderr_fh.close()  # 父进程关闭自己的 fd，子进程保留继承的副本
                self._monitor_proc = proc
                self._tracked_pids.append(proc.pid)
            except Exception:
                return None

            # 等待 Monitor 就绪 (最多 10 秒)
            ready = False
            for _ in range(50):
                time.sleep(0.2)
                pid_file = _pid_file_path()
                if os.path.isfile(pid_file):
                    try:
                        with open(pid_file, "r") as f:
                            written_pid = int(f.read().strip())
                        if self._is_pid_alive(written_pid):
                            ready = True
                            break
                    except (ValueError, OSError):
                        pass

            if not ready:
                # Monitor 进程可能已启动但尚未写入 PID → 用 proc.pid 兜底
                if proc.poll() is None:  # 进程仍存活
                    self._write_pid_file(proc.pid)
                else:
                    # 进程已退出 → 启动失败
                    self._monitor_proc = None
                    return None

            return self._check_status()

    def _clean_stale_pid_file(self):
        """清理过期的 PID 文件 (内部方法，需在锁内调用)"""
        pid_file = _pid_file_path()
        if not os.path.isfile(pid_file):
            return
        try:
            with open(pid_file, "r") as f:
                old_pid = int(f.read().strip())
            if not self._is_pid_alive(old_pid):
                try:
                    os.remove(pid_file)
                except OSError:
                    pass
        except (ValueError, OSError):
            try:
                os.remove(pid_file)
            except OSError:
                pass

    def _write_pid_file(self, pid: int):
        """写入 PID 文件 (内部方法，需在锁内调用)"""
        pid_file = _pid_file_path()
        try:
            os.makedirs(os.path.dirname(pid_file), exist_ok=True)
            with open(pid_file, "w") as f:
                f.write(str(pid))
        except OSError:
            pass

    # ── Monitor 停止 ──────────────────────────────────────────

    def stop_monitor_auto(self):
        """
        任务完成后自动停止 Monitor (受任务计数保护)。

        仅当所有活跃任务都释放引用后才执行停止。
        由 SSE handler 在任务完成后调用。
        """
        with self._lock:
            self._task_count = max(0, self._task_count - 1)
            if self._task_count > 0:
                return  # 还有其他活跃任务

        self._do_stop(clean_pid=True)

    def stop_monitor_forced(self):
        """
        强制停止 Monitor (不受任务计数限制)。

        用于用户手动点击"停止 Monitor"按钮。
        录制和实时监测功能使用此方法。
        """
        self._do_stop(clean_pid=True)

    def _do_stop(self, clean_pid: bool = True):
        """
        执行停止操作 (内部方法)。

        步骤:
          1. 发送 SIGTERM
          2. 等待最多 5 秒
          3. 未退出则 SIGKILL
          4. 清理 PID 文件
        """
        pid_to_kill = None

        # 优先从 PID 文件获取
        pid_file = _pid_file_path()
        if os.path.isfile(pid_file):
            try:
                with open(pid_file, "r") as f:
                    pid_to_kill = int(f.read().strip())
            except (ValueError, OSError):
                pass

        # 回退: 使用子进程对象
        if pid_to_kill is None and self._monitor_proc is not None:
            pid_to_kill = self._monitor_proc.pid

        if pid_to_kill is None:
            # 最后回退: 通过进程名查找
            zombies = self._find_monitor_processes()
            if zombies:
                pid_to_kill = zombies[0]

        if pid_to_kill is None:
            self._cleanup_resources()
            return

        # 发送 SIGTERM
        try:
            os.kill(pid_to_kill, signal.SIGTERM)
        except OSError:
            pass

        # 等待退出
        for _ in range(25):  # 5 秒
            time.sleep(0.2)
            try:
                os.kill(pid_to_kill, 0)
            except OSError:
                break  # 已退出
        else:
            # 仍未退出 → SIGKILL
            try:
                os.kill(pid_to_kill, signal.SIGKILL)
                time.sleep(0.5)
            except OSError:
                pass

        # 清理子进程对象
        if self._monitor_proc is not None:
            try:
                self._monitor_proc.wait(timeout=1)
            except (subprocess.TimeoutExpired, OSError):
                pass
            self._monitor_proc = None

        # 清理资源
        if clean_pid:
            self._cleanup_resources()

    def _cleanup_resources(self):
        """清理 PID 文件和 FIFO (内部方法)"""
        pid_file = _pid_file_path()
        if os.path.isfile(pid_file):
            try:
                os.remove(pid_file)
            except OSError:
                pass

        # FIFO 清理: 仅在无 Monitor 进程时
        remaining = self._find_monitor_processes()
        if not remaining:
            fifo = _fifo_path()
            if os.path.exists(fifo):
                try:
                    os.remove(fifo)
                except OSError:
                    pass

    # ── 状态查询 ──────────────────────────────────────────────

    def status(self) -> Dict:
        """获取 Monitor 运行状态"""
        with self._lock:
            return self._check_status()

    def _check_status(self) -> Dict:
        """检查 Monitor 状态 (内部方法，需在锁内调用)"""
        monitor_running = False
        monitor_pid = None

        pid_file = _pid_file_path()
        if os.path.isfile(pid_file):
            try:
                with open(pid_file, "r") as f:
                    monitor_pid = int(f.read().strip())
                if self._is_pid_alive(monitor_pid):
                    monitor_running = True
                else:
                    monitor_pid = None
            except (ValueError, OSError):
                monitor_pid = None

        # 回退: 检查子进程对象
        if not monitor_running and self._monitor_proc is not None:
            if self._monitor_proc.poll() is None:
                monitor_running = True
                monitor_pid = self._monitor_proc.pid

        fifo = _fifo_path()
        return {
            "monitor_running": monitor_running,
            "monitor_pid": monitor_pid,
            "fifo_path": fifo,
            "fifo_exists": os.path.exists(fifo),
            "pid_file": pid_file,
            "task_count": self._task_count,
        }

    @staticmethod
    def _is_pid_alive(pid: int) -> bool:
        """
        检查 PID 对应的进程是否真正存活（非僵尸）。

        os.kill(pid, 0) 对僵尸进程也返回成功，
        必须通过 /proc/<pid>/stat 的状态字段区分。
        """
        try:
            os.kill(pid, 0)
        except OSError:
            return False
        # 检查是否为僵尸进程 (state == 'Z')
        try:
            with open(f'/proc/{pid}/stat', 'r') as f:
                stat_content = f.read().strip()
            # stat 格式: pid (comm) state ...
            # 定位 state 字符: 在最后一个 ')' 之后
            rparen = stat_content.rfind(')')
            if rparen >= 0 and rparen + 2 < len(stat_content):
                state = stat_content[rparen + 2]
                return state != 'Z'
        except Exception:
            pass
        # 回退: 尝试 reap 僵尸 (仅对子进程有效)
        try:
            reaped_pid, _status = os.waitpid(pid, os.WNOHANG)
            if reaped_pid == pid:
                return False  # 僵尸进程已被 reap
        except OSError:
            pass
        return True

    # ── 任务引用计数 ──────────────────────────────────────────

    def acquire_task(self):
        """
        注册一个依赖 Monitor 的活跃任务。

        在 SSE handler 开始时调用，防止其他任务完成后过早关闭 Monitor。
        """
        with self._lock:
            self._task_count += 1

    def release_task(self):
        """
        释放一个任务引用。

        如果引用计数归零且非 shutting_down，触发自动停止。
        """
        self.stop_monitor_auto()

    @contextmanager
    def task_scope(self):
        """
        任务作用域上下文管理器。

        自动处理 acquire/release，包括异常路径。

        Usage:
            with mgr.task_scope():
                mgr.start_monitor()
                # ... 执行任务 ...
            # 退出时自动 release_task()
        """
        self.acquire_task()
        try:
            yield
        finally:
            self.release_task()

    # ── 系统关闭 ──────────────────────────────────────────────

    def shutdown(self):
        """
        系统关闭时执行完整清理。

        步骤:
          1. 标记 shutting_down (阻止新的自动停止)
          2. 终止所有追踪的 Monitor 进程 (SIGTERM → SIGKILL)
          3. 清理 PID 文件和 FIFO
          4. 重置内部状态
        """
        with self._lock:
            self._shutting_down = True

        # 1. 终止所有追踪的进程
        for pid in list(self._tracked_pids):
            try:
                os.kill(pid, signal.SIGTERM)
            except OSError:
                pass

        if self._tracked_pids:
            time.sleep(1.5)
            for pid in list(self._tracked_pids):
                try:
                    os.kill(pid, 0)
                    os.kill(pid, signal.SIGKILL)
                except OSError:
                    pass

        # 2. 终止任何遗漏的 monitor_daemon.py 进程
        for pid in self._find_monitor_processes():
            try:
                os.kill(pid, signal.SIGTERM)
            except OSError:
                pass
        time.sleep(0.5)
        for pid in self._find_monitor_processes():
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass

        # 3. 等待子进程对象
        if self._monitor_proc is not None:
            try:
                self._monitor_proc.wait(timeout=2)
            except (subprocess.TimeoutExpired, OSError):
                pass
            self._monitor_proc = None

        # 4. 清理资源
        self._cleanup_resources()

        # 5. 重置状态
        with self._lock:
            self._task_count = 0
            self._tracked_pids.clear()
            self._shutting_down = False


# ── 便捷函数 (兼容旧代码) ─────────────────────────────────────

def startup_cleanup() -> Dict:
    """启动时清理所有残留 Monitor 进程和资源"""
    return MonitorLifecycleManager.instance().startup_cleanup()


def shutdown_cleanup():
    """关闭时终止所有 Monitor 并清理资源"""
    MonitorLifecycleManager.instance().shutdown()


def ensure_monitor_running(record: bool = False) -> Optional[Dict]:
    """确保 Monitor 运行 (兼容旧 _ensure_monitor_running 接口)"""
    return MonitorLifecycleManager.instance().start_monitor(record=record)


def get_monitor_status() -> Dict:
    """获取 Monitor 状态 (兼容旧 _get_monitor_status 接口)"""
    return MonitorLifecycleManager.instance().status()


def stop_monitor_auto():
    """任务完成后自动停止 Monitor (受任务计数保护)"""
    MonitorLifecycleManager.instance().stop_monitor_auto()


def stop_monitor_forced():
    """强制停止 Monitor (不受任务计数限制)"""
    MonitorLifecycleManager.instance().stop_monitor_forced()


def acquire_task():
    """注册活跃任务"""
    MonitorLifecycleManager.instance().acquire_task()


def release_task():
    """释放任务引用"""
    MonitorLifecycleManager.instance().release_task()
