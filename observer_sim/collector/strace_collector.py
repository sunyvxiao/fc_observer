"""
collector/strace_collector.py — strace 降级采集器

实现 ICollector 接口，通过 subprocess 启动 strace 进程，
逐行解析 strace 输出并转换为 RawEvent yield 给上层。

当 eBPF 不可用时自动降级为此模式。
第一版仅做观测，send_command() 返回 False（不支持阻断）。

依赖:
  - strace (apt install strace)
  - Linux 系统
"""

import os
import re
import time
import signal
import logging
import subprocess
import threading
import queue
from typing import Iterator, Optional

from collector.base_collector import ICollector, CollectorCapabilities
from models.event import RawEvent

logger = logging.getLogger(__name__)

# ============================================================
# strace 输出行解析正则
# ============================================================

# execve 示例:
#   12345 execve("/bin/ls", ["ls", "-la", "/tmp"], 0x7fff... /* 20 vars */) = 0
#   [pid 12345] execve("/bin/ls", ["ls", "-la"], ["HOME=/home/user", ...]) = 0
_RE_EXECVE = re.compile(
    r'(?:\[pid\s+(\d+)\]\s+)?'          # 可选 [pid NNN]
    r'execve\('
    r'"([^"]*)"'                         # filename
    r',\s*\[([^\]]*)\]'                  # argv (逗号分隔列表)
    r'.*?'
    r'\)\s*=\s*(\S+)'                    # 返回值
)

# openat 示例:
#   12345 openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 3
#   [pid 12345] openat(AT_FDCWD, "/tmp/test.txt", O_WRONLY|O_CREAT, 0644) = 3
_RE_OPENAT = re.compile(
    r'(?:\[pid\s+(\d+)\]\s+)?'          # 可选 [pid NNN]
    r'openat\('
    r'(?:AT_FDCWD|-?\d+)'               # dirfd
    r',\s*"([^"]*)"'                     # filename
    r',\s*([^)]+)'                       # flags
    r'\)\s*=\s*(\S+)'                    # 返回值
)

# connect 示例:
#   12345 connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("93.184.216.34")}, 16) = 0
#   [pid 12345] connect(3, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("8.8.8.8")}, 16) = 0
_RE_CONNECT = re.compile(
    r'(?:\[pid\s+(\d+)\]\s+)?'          # 可选 [pid NNN]
    r'connect\('
    r'(\d+)'                             # sockfd
    r',\s*\{sa_family=AF_INET'
    r',\s*sin_port=htons\((\d+)\)'      # port
    r',\s*sin_addr=inet_addr\("([^"]+)"\)'  # IP
)

# 通用 syscall 行匹配（提取 PID 和 syscall 名称）
_RE_SYSCALL_LINE = re.compile(
    r'(?:\[pid\s+(\d+)\]\s+)?'          # 可选 [pid NNN]
    r'(\w+)\('                           # syscall name
)


# ============================================================
# StraceCollector 实现
# ============================================================

class StraceCollector(ICollector):
    """
    strace 降级采集器 —— 通过 subprocess 调用 strace，
    逐行解析输出并转换为 RawEvent。

    当 eBPF 不可用时自动降级为此模式。
    第一版仅做观测，不支持阻断。
    """

    def __init__(self, config: dict):
        """
        初始化 strace 采集器。

        参数:
            config: 配置字典（从 config.yaml 加载）
        """
        self.config = config
        self.strace_config = config.get("strace", {})
        self.strace_bin = self.strace_config.get("strace_bin", "strace")
        self.target_agent_id = self.strace_config.get(
            "target_agent_id", "observed-agent")

        # 内部状态
        self._process: Optional[subprocess.Popen] = None
        self._attached = False
        self._running = False
        self._target_pid: int = 0
        self._seq = 0
        self._line_queue = queue.Queue(maxsize=10000)
        self._reader_thread: Optional[threading.Thread] = None

    def capabilities(self) -> CollectorCapabilities:
        """返回 strace 采集器能力描述"""
        return CollectorCapabilities(
            name="Strace",
            can_observe=True,
            can_block_tier2=False,    # 不支持阻断
            can_block_tier3=False,    # 不支持阻断
            is_transparent=False,     # strace -p 会附着到进程，非完全透明
            performance_overhead="medium",
            time_source="realtime_monotonic",
        )

    def attach(self, target_pid: int = 0, agent_id: str = "") -> bool:
        """
        启动 strace 子进程附着到目标进程。

        参数:
            target_pid: 目标进程 PID
            agent_id:   Agent 标识

        返回:
            True:  strace 启动成功
            False: strace 不可用或权限不足
        """
        if agent_id:
            self.target_agent_id = agent_id

        if target_pid <= 0:
            logger.error(f"无效的 target_pid: {target_pid}")
            return False

        # 检查 strace 是否可用
        if not self._check_strace_available():
            return False

        self._target_pid = target_pid

        try:
            # 构建 strace 命令
            cmd = [
                self.strace_bin,
                "-f",              # 跟踪子进程
                "-tt",             # 微秒精度时间戳
                "-e",
                "trace=execve,openat,connect",  # 只跟踪三类 syscall
                "-p", str(target_pid),
                "-o", "/dev/stdout",  # 输出到 stdout
            ]

            # 如果配置了 strace 输出文件，使用文件
            output_file = self.strace_config.get("output_file")
            if output_file:
                cmd = [
                    self.strace_bin,
                    "-f", "-tt",
                    "-e", "trace=execve,openat,connect",
                    "-p", str(target_pid),
                    "-o", output_file,
                ]

            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,  # 行缓冲
            )

            self._attached = True
            self._running = True

            # 启动读取线程
            self._reader_thread = threading.Thread(
                target=self._read_loop, daemon=True, name="strace-reader")
            self._reader_thread.start()

            logger.info(
                f"StraceCollector 已附着到 PID {target_pid} "
                f"(agent_id={self.target_agent_id})")
            return True

        except FileNotFoundError:
            logger.error(f"strace 可执行文件不存在: {self.strace_bin}")
            return False
        except PermissionError:
            logger.error(f"权限不足，无法 strace PID {target_pid}")
            return False
        except Exception as e:
            logger.error(f"StraceCollector attach 异常: {e}")
            return False

    def _check_strace_available(self) -> bool:
        """检查 strace 是否可用"""
        try:
            result = subprocess.run(
                [self.strace_bin, "-V"],
                capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                version_line = result.stdout.strip().split("\n")[0]
                logger.info(f"strace 可用: {version_line}")
                return True
            else:
                logger.error(f"strace 返回错误: {result.stderr}")
                return False
        except FileNotFoundError:
            logger.error("strace 未安装或不在 PATH 中")
            return False
        except Exception as e:
            logger.error(f"检查 strace 可用性失败: {e}")
            return False

    def _read_loop(self):
        """从 strace stdout 逐行读取并放入队列"""
        try:
            while self._running and self._process:
                line = self._process.stdout.readline()
                if not line:
                    # strace 进程结束
                    break
                line = line.strip()
                if line:
                    try:
                        self._line_queue.put_nowait(line)
                    except queue.Full:
                        logger.warning("strace 行队列已满，丢弃行")
        except Exception as e:
            if self._running:
                logger.error(f"strace 读取线程异常: {e}")
        finally:
            self._running = False

    def _parse_line(self, line: str) -> Optional[RawEvent]:
        """
        解析单行 strace 输出为 RawEvent。

        支持三种格式:
          - execve: 'execve("/bin/ls", ["ls", "-la"], ...) = 0'
          - openat: 'openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 3'
          - connect: 'connect(3, {sa_family=AF_INET, sin_port=htons(443), ...}) = 0'

        参数:
            line: strace 输出的一行文本

        返回:
            RawEvent 或 None（无法解析时）
        """
        # 提取 PID（可能在前缀 [pid NNN] 中）
        pid = self._target_pid

        # 尝试匹配 execve
        m = _RE_EXECVE.search(line)
        if m:
            if m.group(1):
                pid = int(m.group(1))
            filename = m.group(2)
            argv_str = m.group(3)
            ret_val = m.group(4)

            # 只处理成功的调用
            if ret_val != "0":
                return None

            # 解析 argv
            arguments = []
            if argv_str.strip():
                # 去除引号，按逗号分割
                for arg in argv_str.split(","):
                    arg = arg.strip().strip('"')
                    if arg:
                        arguments.append(arg)

            self._seq += 1
            return RawEvent(
                event_id=f"strace_evt_{self._seq:06d}",
                timestamp_ns=time.time_ns(),
                event_type="exec",
                pid=pid,
                ppid=self._target_pid,
                agent_id=self.target_agent_id,
                agent_framework="strace",
                executable=filename,
                arguments=arguments if arguments else None,
            )

        # 尝试匹配 openat
        m = _RE_OPENAT.search(line)
        if m:
            if m.group(1):
                pid = int(m.group(1))
            filename = m.group(2)
            flags_str = m.group(3)
            ret_val = m.group(4)

            # 只处理成功的调用（返回值 >= 0）
            try:
                ret_int = int(ret_val)
                if ret_int < 0:
                    return None
            except ValueError:
                return None

            # flags 映射
            file_op = "read"
            if "O_WRONLY" in flags_str or "O_RDWR" in flags_str:
                file_op = "write"
            elif "O_CREAT" in flags_str:
                file_op = "write"

            self._seq += 1
            return RawEvent(
                event_id=f"strace_evt_{self._seq:06d}",
                timestamp_ns=time.time_ns(),
                event_type="file_open",
                pid=pid,
                ppid=self._target_pid,
                agent_id=self.target_agent_id,
                agent_framework="strace",
                file_path=filename,
                file_op=file_op,
            )

        # 尝试匹配 connect
        m = _RE_CONNECT.search(line)
        if m:
            if m.group(1):
                pid = int(m.group(1))
            port = int(m.group(3))
            ip_addr = m.group(4)

            self._seq += 1
            return RawEvent(
                event_id=f"strace_evt_{self._seq:06d}",
                timestamp_ns=time.time_ns(),
                event_type="net_conn",
                pid=pid,
                ppid=self._target_pid,
                agent_id=self.target_agent_id,
                agent_framework="strace",
                remote_addr=ip_addr,
                remote_port=port,
                protocol="TCP",  # connect() 默认 TCP
            )

        # 无法匹配已知格式
        return None

    def start(self) -> Iterator[RawEvent]:
        """
        开始采集，从 strace 输出行队列中解析并 yield RawEvent。
        """
        if not self._attached:
            logger.warning("StraceCollector 未附着，请先调用 attach()")
            return

        while self._running:
            try:
                line = self._line_queue.get(timeout=1.0)
                raw = self._parse_line(line)
                if raw:
                    yield raw
            except queue.Empty:
                # 检查 strace 进程是否还活着
                if self._process and self._process.poll() is not None:
                    logger.info("strace 进程已退出")
                    break
                continue

    def send_command(self, cmd) -> bool:
        """
        strace 模式不支持阻断。

        返回 False 并记录警告日志。
        """
        logger.warning(
            "strace 模式不支持阻断，send_command() 忽略。"
            "如需阻断功能，请使用 eBPF 模式")
        return False

    def detach(self) -> None:
        """断开采集，终止 strace 子进程"""
        self._running = False

        if self._process:
            try:
                self._process.terminate()
                self._process.wait(timeout=5)
                logger.info("strace 进程已终止")
            except subprocess.TimeoutExpired:
                logger.warning("strace 进程终止超时，强制 kill")
                self._process.kill()
                self._process.wait(timeout=2)
            except Exception as e:
                logger.error(f"终止 strace 进程异常: {e}")
            finally:
                self._process = None

        if self._reader_thread and self._reader_thread.is_alive():
            self._reader_thread.join(timeout=2.0)

        self._attached = False
        logger.info("StraceCollector 已断开")

    def get_process_tree(self) -> dict:
        """
        获取进程树快照。

        strace 模式下从 /proc/{pid}/stat 构建简单的进程树。
        第一版简化实现，返回空字典。
        """
        # TODO: 从 /proc/{pid}/stat 构建进程树
        return {}
