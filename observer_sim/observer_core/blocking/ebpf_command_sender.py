"""
blocking/ebpf_command_sender.py — eBPF 阻断指令发送器

实现 ICommandSender 接口，通过 libbpf ctypes 直接操作 block_policy map
和挂载 kprobe 探针，实现真实的 syscall 级阻断。

与 EbpfCollector 的区别:
- EbpfCollector: 完整的 eBPF 采集器（tracepoint观测 + ring buffer消费 + 阻断）
- EbpfCommandSender: 轻量级发送器，仅加载 bpf_object 用于阻断，不启动观测

降级策略 (三级):
  L0: 正常模式 — libbpf 可用 + BTF 支持 + root 权限
  L1: 降级模式 — libbpf 不可用 / BTF 不支持 / 非 root → MockCommandSender + 告警
  L2: 恢复检测 — 周期性尝试重新加载 (每 30s)

用法:
    sender = EbpfCommandSender()
    if sender.is_degraded:
        print(f"eBPF 降级: {sender.degradation_reason}")
    else:
        sender.connect("block_policy")
        sender.send_command(Command.make_block(...))
"""

import os
import sys
import ctypes
import logging
import time
import threading
from typing import Optional, Set, List

from observer_core.blocking.command_sender import ICommandSender
from models.command import Command, CmdType

logger = logging.getLogger(__name__)

# ── libbpf 动态加载 ──────────────────────────────────────────────────────────

_libbpf = None
_LIBBPF_SEARCH_PATHS = [
    "libbpf.so",
    "/usr/local/lib/libbpf.so",
    "libbpf.so.1",
]


def _load_libbpf() -> Optional[ctypes.CDLL]:
    """延迟加载 libbpf.so"""
    global _libbpf
    if _libbpf is not None:
        return _libbpf
    for path in _LIBBPF_SEARCH_PATHS:
        try:
            _libbpf = ctypes.CDLL(path)
            logger.info(f"EbpfCommandSender: libbpf 加载成功: {path}")
            return _libbpf
        except OSError:
            continue
    return None


def _setup_libbpf_signatures(lib: ctypes.CDLL):
    """设置 libbpf 函数签名（仅阻断所需的最小集合）"""
    # struct bpf_object *bpf_object__open(const char *path)
    lib.bpf_object__open.argtypes = [ctypes.c_char_p]
    lib.bpf_object__open.restype = ctypes.c_void_p

    # int bpf_object__load(struct bpf_object *obj)
    lib.bpf_object__load.argtypes = [ctypes.c_void_p]
    lib.bpf_object__load.restype = ctypes.c_int

    # void bpf_object__close(struct bpf_object *obj)
    lib.bpf_object__close.argtypes = [ctypes.c_void_p]
    lib.bpf_object__close.restype = None

    # struct bpf_program *bpf_object__find_program_by_name(obj, name)
    lib.bpf_object__find_program_by_name.argtypes = [
        ctypes.c_void_p, ctypes.c_char_p]
    lib.bpf_object__find_program_by_name.restype = ctypes.c_void_p

    # int bpf_program__fd(const struct bpf_program *prog)
    lib.bpf_program__fd.argtypes = [ctypes.c_void_p]
    lib.bpf_program__fd.restype = ctypes.c_int

    # struct bpf_link *bpf_program__attach(const struct bpf_program *prog)
    lib.bpf_program__attach.argtypes = [ctypes.c_void_p]
    lib.bpf_program__attach.restype = ctypes.c_void_p

    # void bpf_link__destroy(struct bpf_link *link)
    lib.bpf_link__destroy.argtypes = [ctypes.c_void_p]
    lib.bpf_link__destroy.restype = None

    # int bpf_object__find_map_fd_by_name(obj, name)
    lib.bpf_object__find_map_fd_by_name.argtypes = [
        ctypes.c_void_p, ctypes.c_char_p]
    lib.bpf_object__find_map_fd_by_name.restype = ctypes.c_int

    # int bpf_map_update_elem(int fd, const void *key, const void *value, __u64 flags)
    lib.bpf_map_update_elem.argtypes = [
        ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint64]
    lib.bpf_map_update_elem.restype = ctypes.c_int

    # int bpf_map_delete_elem(int fd, const void *key)
    lib.bpf_map_delete_elem.argtypes = [ctypes.c_int, ctypes.c_void_p]
    lib.bpf_map_delete_elem.restype = ctypes.c_int

    # int bpf_map_lookup_elem(int fd, const void *key, void *value)
    lib.bpf_map_lookup_elem.argtypes = [
        ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
    lib.bpf_map_lookup_elem.restype = ctypes.c_int

    # const char *libbpf_strerror(int err)
    try:
        lib.libbpf_strerror.argtypes = [ctypes.c_int]
        lib.libbpf_strerror.restype = ctypes.c_char_p
    except AttributeError:
        pass


# ── eBPF 可用性检测 ──────────────────────────────────────────────────────────

def detect_ebpf_capability() -> dict:
    """
    检测 eBPF 环境是否可用。

    Returns:
        {"available": bool, "reason": str, "details": dict}
    """
    details = {
        "is_root": os.name == "posix" and os.geteuid() == 0,
        "has_btf": os.path.exists("/sys/kernel/btf/vmlinux"),
        "has_libbpf": _load_libbpf() is not None,
    }
    details["available"] = details["is_root"] and details["has_btf"] and details["has_libbpf"]

    if not details["is_root"]:
        reason = "缺少 root 权限（eBPF 程序加载需要 CAP_SYS_ADMIN）"
    elif not details["has_btf"]:
        reason = "内核不支持 BTF（/sys/kernel/btf/vmlinux 不存在）"
    elif not details["has_libbpf"]:
        reason = "libbpf.so 未安装（apt install libbpf-dev 或手动编译）"
    else:
        reason = "eBPF 环境可用"

    return {"available": details["available"], "reason": reason, "details": details}


# ── block_flags 常量 ─────────────────────────────────────────────────────────

BLOCK_EXECVE = 0x01
BLOCK_OPENAT = 0x02
BLOCK_CONNECT = 0x04
BLOCK_ALL = BLOCK_EXECVE | BLOCK_OPENAT | BLOCK_CONNECT


class EbpfCommandSender(ICommandSender):
    """
    eBPF 阻断指令发送器 —— 实现 ICommandSender 接口。

    通过 libbpf ctypes 直接操作 block_policy eBPF map 和动态挂载 kprobe。
    不依赖 EbpfCollector，可独立使用。
    """

    # 三个 kprobe 探针名称（与 observer.bpf.c 一致）
    _KPROBE_NAMES = [b"kprobe__execve", b"kprobe__openat", b"kprobe__connect"]

    def __init__(self, bpf_object_path: str = None):
        """
        Args:
            bpf_object_path: eBPF 字节码路径，默认自动查找
        """
        self._connected: bool = False
        self._cmd_counter: int = 0
        self._commands: List[Command] = []  # 已发送的指令记录

        # eBPF 资源
        self._lib: Optional[ctypes.CDLL] = None
        self._bpf_object = None
        self._kprobe_links: list = []
        self._kprobe_attached: bool = False
        self._blocked_pids: Set[int] = set()
        self._block_policy_fd: int = -1

        # 降级状态
        self._degraded: bool = True
        self._degradation_reason: str = ""
        self._degradation_time: float = 0.0

        # 恢复检测线程
        self._recovery_thread: Optional[threading.Thread] = None
        self._recovery_stop: bool = False

        # 确定 bpf_object_path
        if bpf_object_path:
            self._bpf_object_path = bpf_object_path
        else:
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(
                os.path.abspath(__file__))))
            self._bpf_object_path = os.path.join(base_dir, "ebpf", "observer.bpf.o")

        # 尝试初始化
        self._try_init()

    # ── 初始化与降级 ────────────────────────────────────────────────────────

    def _try_init(self) -> bool:
        """尝试初始化 eBPF 子系统，失败则标记降级"""
        cap = detect_ebpf_capability()
        if not cap["available"]:
            self._degraded = True
            self._degradation_reason = cap["reason"]
            self._degradation_time = time.time()
            logger.warning(f"EbpfCommandSender 降级: {self._degradation_reason}")
            return False

        # 检查 bpf_object 文件
        if not os.path.isfile(self._bpf_object_path):
            self._degraded = True
            self._degradation_reason = (
                f"eBPF 字节码不存在: {self._bpf_object_path}")
            self._degradation_time = time.time()
            logger.warning(f"EbpfCommandSender 降级: {self._degradation_reason}")
            return False

        # 加载 libbpf
        self._lib = _load_libbpf()
        if self._lib is None:
            self._degraded = True
            self._degradation_reason = "libbpf.so 加载失败"
            self._degradation_time = time.time()
            return False

        _setup_libbpf_signatures(self._lib)

        # 加载 bpf_object
        try:
            bpf_path_bytes = self._bpf_object_path.encode("utf-8")
            self._bpf_object = self._lib.bpf_object__open(bpf_path_bytes)
            if not self._bpf_object:
                self._degraded = True
                self._degradation_reason = "bpf_object__open 返回 NULL"
                self._degradation_time = time.time()
                logger.error(self._degradation_reason)
                return False

            ret = self._lib.bpf_object__load(self._bpf_object)
            if ret != 0:
                self._degraded = True
                self._degradation_reason = (
                    f"bpf_object__load 失败 (ret={ret})")
                self._degradation_time = time.time()
                logger.error(self._degradation_reason)
                self._cleanup_bpf()
                return False

            self._degraded = False
            self._degradation_reason = ""
            logger.info("EbpfCommandSender: eBPF 初始化成功")
            return True

        except Exception as e:
            self._degraded = True
            self._degradation_reason = f"eBPF 初始化异常: {e}"
            self._degradation_time = time.time()
            logger.error(self._degradation_reason)
            return False

    def _cleanup_bpf(self):
        """清理 eBPF 资源"""
        self._detach_kprobes()
        if self._bpf_object is not None:
            try:
                self._lib.bpf_object__close(self._bpf_object)
            except Exception:
                pass
            self._bpf_object = None
        self._block_policy_fd = -1

    def _libbpf_strerror(self, err: int) -> str:
        """将 libbpf 错误码转换为可读字符串"""
        if self._lib is None:
            return f"errno={err}"
        try:
            return self._lib.libbpf_strerror(err).decode("utf-8", errors="replace")
        except Exception:
            return f"errno={err}"

    # ── kprobe 管理 ─────────────────────────────────────────────────────────

    def _get_block_policy_fd(self) -> int:
        """获取 block_policy map 文件描述符"""
        if self._block_policy_fd >= 0:
            return self._block_policy_fd
        if not self._bpf_object or self._lib is None:
            return -1
        self._block_policy_fd = self._lib.bpf_object__find_map_fd_by_name(
            self._bpf_object, b"block_policy")
        if self._block_policy_fd < 0:
            logger.error(f"找不到 block_policy map: fd={self._block_policy_fd}")
        return self._block_policy_fd

    def _update_block_policy(self, pid: int, flags: int) -> bool:
        """更新 block_policy map"""
        if self._lib is None:
            return False
        map_fd = self._get_block_policy_fd()
        if map_fd < 0:
            return False
        key = ctypes.c_uint32(pid)
        value = ctypes.c_uint64(flags)
        ret = self._lib.bpf_map_update_elem(
            map_fd, ctypes.byref(key), ctypes.byref(value), 0)
        if ret != 0:
            logger.error(
                f"bpf_map_update_elem(block_policy, pid={pid}, flags=0x{flags:x}) "
                f"失败: {self._libbpf_strerror(ret)}")
            return False
        logger.info(f"block_policy 已更新: pid={pid}, flags=0x{flags:x}")
        return True

    def _delete_block_policy(self, pid: int) -> bool:
        """从 block_policy map 删除条目"""
        if self._lib is None:
            return False
        map_fd = self._get_block_policy_fd()
        if map_fd < 0:
            return False
        key = ctypes.c_uint32(pid)
        ret = self._lib.bpf_map_delete_elem(map_fd, ctypes.byref(key))
        if ret != 0:
            if ret == -2 or ret == 2:  # ENOENT
                logger.debug(f"block_policy pid={pid} 不存在，无需删除")
                return True
            logger.error(
                f"bpf_map_delete_elem(block_policy, pid={pid}) 失败: "
                f"{self._libbpf_strerror(ret)}")
            return False
        logger.info(f"block_policy 已删除: pid={pid}")
        return True

    def _ensure_kprobes_attached(self) -> bool:
        """确保 kprobe 阻断探针已挂载（首次阻断时调用）"""
        if self._kprobe_attached:
            return True
        if not self._bpf_object or self._lib is None:
            logger.error("bpf_object 未加载，无法挂载 kprobe")
            return False

        for name in self._KPROBE_NAMES:
            prog = self._lib.bpf_object__find_program_by_name(
                self._bpf_object, name)
            if not prog:
                logger.error(
                    f"找不到 kprobe 程序: {name.decode()}，请确认 observer.bpf.o 已重新编译")
                self._detach_kprobes()
                return False

            fd = self._lib.bpf_program__fd(prog)
            logger.info(f"[阻断] 挂载 kprobe: {name.decode()} (fd={fd})")

            link = self._lib.bpf_program__attach(prog)
            if not link:
                logger.error(
                    f"kprobe {name.decode()} attach 失败，可能需要 root 权限")
                self._detach_kprobes()
                return False

            self._kprobe_links.append(link)
            logger.info(f"[阻断] kprobe 已挂载: {name.decode()}")

        self._kprobe_attached = True
        logger.info("[阻断] 全部 3 个 kprobe 已挂载，阻断能力已激活")
        return True

    def _detach_kprobes(self) -> None:
        """卸载所有 kprobe 阻断探针"""
        if not self._kprobe_links or self._lib is None:
            self._kprobe_attached = False
            return

        for link in self._kprobe_links:
            try:
                self._lib.bpf_link__destroy(link)
            except Exception as e:
                logger.warning(f"kprobe link destroy 异常: {e}")

        self._kprobe_links.clear()
        self._kprobe_attached = False
        logger.info("[阻断] kprobe 探针已卸载")

    def _resolve_block_flags(self, cmd: Command) -> int:
        """从 Command 解析 block_flags"""
        if cmd.cmd_type == CmdType.BLOCK_EVENT.value:
            return BLOCK_ALL
        elif cmd.cmd_type == CmdType.TERMINATE_PROCESS.value:
            return BLOCK_ALL
        elif cmd.cmd_type == CmdType.ALLOW.value:
            return 0
        else:
            return -1

    # ── ICommandSender 接口实现 ─────────────────────────────────────────────

    def connect(self, pipe_name: str) -> bool:
        """
        连接（eBPF 模式下为 no-op，已在 __init__ 中初始化）。

        Args:
            pipe_name: 忽略（保持接口兼容）
        """
        self._connected = True
        if self._degraded:
            logger.warning(
                f"EbpfCommandSender 在降级模式下连接: {self._degradation_reason}")
        return True

    def send_command(self, cmd: Command) -> bool:
        """
        发送阻断指令到 eBPF 内核探针。

        流程:
          1. 检查降级状态
          2. 解析 Command → pid + flags
          3. 更新/删除 block_policy map
          4. 动态挂载/卸载 kprobe
        """
        # 记录指令
        self._commands.append(cmd)
        self._cmd_counter += 1

        if self._degraded:
            logger.debug(
                f"EbpfCommandSender 降级，指令记录但不执行: "
                f"{cmd.cmd_type} -> {cmd.target_pid}")
            return False

        target_pid = cmd.target_pid
        if not target_pid or target_pid <= 0:
            logger.debug(f"Command 缺少有效的 target_pid: {target_pid}")
            return False

        block_flags = self._resolve_block_flags(cmd)
        if block_flags < 0:
            logger.debug(f"Command 类型 {cmd.cmd_type} 不适用于 eBPF 阻断")
            return False

        if block_flags == 0:
            # 解除阻断
            logger.info(
                f"[阻断] 解除 PID {target_pid} 的阻断 "
                f"(cmd_id={cmd.cmd_id}, reason={cmd.reason})")
            if not self._delete_block_policy(target_pid):
                return False
            self._blocked_pids.discard(target_pid)
            if not self._blocked_pids:
                self._detach_kprobes()
                logger.info("[阻断] 所有 PID 已解除阻断，kprobe 已卸载")
            return True
        else:
            # 设置阻断
            logger.info(
                f"[阻断] 阻断 PID {target_pid} "
                f"(cmd_id={cmd.cmd_id}, flags=0x{block_flags:x}, "
                f"reason={cmd.reason})")
            if not self._ensure_kprobes_attached():
                logger.error(
                    f"[阻断] kprobe 挂载失败，PID {target_pid} 阻断未生效")
                return False
            if not self._update_block_policy(target_pid, block_flags):
                return False
            self._blocked_pids.add(target_pid)
            return True

    def disconnect(self) -> None:
        """断开连接，清理 eBPF 资源"""
        self._connected = False
        self._detach_kprobes()
        self._cleanup_bpf()
        self._commands.clear()

    # ── 降级与恢复 ──────────────────────────────────────────────────────────

    @property
    def is_degraded(self) -> bool:
        """是否处于降级模式"""
        return self._degraded

    @property
    def degradation_reason(self) -> str:
        """降级原因"""
        return self._degradation_reason

    @property
    def degradation_time(self) -> float:
        """降级发生时间（Unix 时间戳）"""
        return self._degradation_time

    def degradation_report(self) -> dict:
        """
        生成降级告警报告（C1 决策：独立告警报告）。

        Returns:
            dict with keys: reason, impact, suggestion, degraded_at, details
        """
        import datetime
        return {
            "alert_type": "ebpf_degradation",
            "reason": self._degradation_reason,
            "impact": (
                "系统已降级为非阻断模式。"
                "所有 BLOCK 级别的决策将仅记录到审计日志，"
                "不会对 Agent 进程执行真实的 syscall 阻断。"
                "建议安全维护人员尽快检查 eBPF 环境配置。"
            ),
            "suggestion": (
                "1. 确认以 root 权限运行 (sudo)\n"
                "2. 确认内核支持 BTF: ls /sys/kernel/btf/vmlinux\n"
                "3. 安装 libbpf-dev: apt install libbpf-dev\n"
                "4. 确认 observer.bpf.o 已编译: ls ebpf/observer.bpf.o"
            ),
            "degraded_at": datetime.datetime.fromtimestamp(
                self._degradation_time).isoformat(),
            "details": detect_ebpf_capability()["details"],
        }

    def try_recover(self) -> bool:
        """尝试从降级状态恢复"""
        if not self._degraded:
            return True
        logger.info("尝试从 eBPF 降级恢复...")
        if self._try_init():
            logger.info("eBPF 恢复成功！")
            return True
        logger.warning(f"eBPF 恢复失败: {self._degradation_reason}")
        return False

    def start_recovery_thread(self, interval: float = 30.0):
        """启动后台恢复检测线程"""
        if self._recovery_thread is not None and self._recovery_thread.is_alive():
            return
        self._recovery_stop = False
        self._recovery_thread = threading.Thread(
            target=self._recovery_loop,
            args=(interval,),
            daemon=True,
            name="ebpf-recovery",
        )
        self._recovery_thread.start()

    def stop_recovery_thread(self):
        """停止恢复检测线程"""
        self._recovery_stop = True
        if self._recovery_thread:
            self._recovery_thread.join(timeout=2.0)
            self._recovery_thread = None

    def _recovery_loop(self, interval: float):
        """恢复检测循环"""
        while not self._recovery_stop:
            time.sleep(interval)
            if self._recovery_stop:
                break
            if self._degraded:
                self.try_recover()

    # ── 测试辅助属性 ────────────────────────────────────────────────────────

    @property
    def is_connected(self) -> bool:
        return self._connected

    @property
    def sent_commands(self) -> list:
        """已发送的指令列表（兼容 MockCommandSender 接口）"""
        return list(self._commands)

    @property
    def last_command(self) -> Optional[Command]:
        """最后一条指令"""
        return self._commands[-1] if self._commands else None

    @property
    def blocked_pids(self) -> Set[int]:
        """当前被阻断的 PID 集合"""
        return set(self._blocked_pids)

    def clear(self) -> None:
        """清空指令记录"""
        self._commands.clear()

    def next_cmd_id(self) -> str:
        self._cmd_counter += 1
        return f"cmd_{self._cmd_counter:04d}"

