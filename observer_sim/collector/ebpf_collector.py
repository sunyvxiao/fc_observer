"""
collector/ebpf_collector.py — eBPF 采集器（Linux 内核探针观测）

实现 ICollector 接口，通过 libbpf (ctypes) 加载预编译的 eBPF 字节码，
挂载三类 tracepoint 探针（execve/openat/connect），消费 perf ring buffer
事件并转换为 RawEvent yield 给上层。

第一版仅做观测，send_command() 返回 False（不支持阻断）。

依赖:
  - libbpf.so (libbpf-dev 包)
  - ebpf/observer.bpf.o (预编译的 eBPF 字节码)
"""

import os
import sys
import ctypes
import struct
import socket
import logging
import threading
import atexit
import queue
from typing import Iterator, Optional

from collector.base_collector import ICollector, CollectorCapabilities
from models.event import RawEvent

logger = logging.getLogger(__name__)

# ============================================================
# libbpf ctypes 绑定
# ============================================================

_libbpf = None


def _load_libbpf():
    """延迟加载 libbpf.so，返回 CDLL 对象"""
    global _libbpf
    if _libbpf is not None:
        return _libbpf
    # 按优先级尝试多个路径
    search_paths = [
        "libbpf.so",               # 系统默认（ldconfig）
        "/usr/local/lib/libbpf.so",  # 手动编译安装
        "libbpf.so.1",             # 带版本号
    ]
    for path in search_paths:
        try:
            _libbpf = ctypes.CDLL(path)
            logger.info(f"libbpf 加载成功: {path}")
            # 尝试获取版本信息
            try:
                _libbpf.libbpf_version_string.restype = ctypes.c_char_p
                ver = _libbpf.libbpf_version_string()
                if ver:
                    logger.info(f"libbpf 版本: {ver.decode()}")
            except (AttributeError, Exception):
                pass
            return _libbpf
        except OSError:
            continue
    raise ImportError(
        f"无法加载 libbpf.so，已尝试路径: {search_paths}。"
        "请确认已安装 libbpf-dev 或手动编译 libbpf >= 1.4")


# libbpf 函数签名定义
def _setup_libbpf_signatures(lib):
    """设置 libbpf 函数的参数和返回类型"""

    # struct bpf_object *bpf_object__open(const char *path)
    lib.bpf_object__open.argtypes = [ctypes.c_char_p]
    lib.bpf_object__open.restype = ctypes.c_void_p

    # int bpf_object__load(struct bpf_object *obj)
    lib.bpf_object__load.argtypes = [ctypes.c_void_p]
    lib.bpf_object__load.restype = ctypes.c_int

    # void bpf_object__close(struct bpf_object *obj)
    lib.bpf_object__close.argtypes = [ctypes.c_void_p]
    lib.bpf_object__close.restype = None

    # struct bpf_program *bpf_object__find_program_by_name(
    #     struct bpf_object *obj, const char *name)
    lib.bpf_object__find_program_by_name.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    lib.bpf_object__find_program_by_name.restype = ctypes.c_void_p

    # int bpf_program__fd(const struct bpf_program *prog)
    lib.bpf_program__fd.argtypes = [ctypes.c_void_p]
    lib.bpf_program__fd.restype = ctypes.c_int

    # struct bpf_link *bpf_program__attach(
    #     const struct bpf_program *prog)
    lib.bpf_program__attach.argtypes = [ctypes.c_void_p]
    lib.bpf_program__attach.restype = ctypes.c_void_p

    # void bpf_link__destroy(struct bpf_link *link)
    lib.bpf_link__destroy.argtypes = [ctypes.c_void_p]
    lib.bpf_link__destroy.restype = None

    # int bpf_object__find_map_fd_by_name(
    #     struct bpf_object *obj, const char *name)
    lib.bpf_object__find_map_fd_by_name.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    lib.bpf_object__find_map_fd_by_name.restype = ctypes.c_int

    # struct perf_buffer *perf_buffer__new(
    #     int map_fd, size_t page_cnt,
    #     perf_buffer_sample_fn sample_cb,
    #     perf_buffer_lost_fn lost_cb,
    #     void *ctx,
    #     const struct perf_buffer_opts *opts)
    lib.perf_buffer__new.argtypes = [
        ctypes.c_int,       # map_fd
        ctypes.c_size_t,    # page_cnt
        ctypes.c_void_p,    # sample_cb (function pointer)
        ctypes.c_void_p,    # lost_cb (function pointer)
        ctypes.c_void_p,    # ctx
        ctypes.c_void_p,    # opts (NULL ok)
    ]
    lib.perf_buffer__new.restype = ctypes.c_void_p

    # 备用: perf_buffer__new_raw (某些旧版本)
    try:
        lib.perf_buffer__new_raw.argtypes = [
            ctypes.c_int, ctypes.c_size_t, ctypes.c_void_p]
        lib.perf_buffer__new_raw.restype = ctypes.c_void_p
    except AttributeError:
        pass

    # int libbpf_get_error(void *ptr) — 用于获取 libbpf 内部 errno
    try:
        lib.libbpf_get_error.argtypes = [ctypes.c_void_p]
        lib.libbpf_get_error.restype = ctypes.c_int
    except AttributeError:
        pass

    # int libbpf_strerror(int err, char *buf, size_t size)
    try:
        lib.libbpf_strerror.argtypes = [
            ctypes.c_int, ctypes.c_char_p, ctypes.c_size_t]
        lib.libbpf_strerror.restype = ctypes.c_int
    except AttributeError:
        pass

    # int perf_buffer__poll(struct perf_buffer *pb, int timeout_ms)
    lib.perf_buffer__poll.argtypes = [ctypes.c_void_p, ctypes.c_int]
    lib.perf_buffer__poll.restype = ctypes.c_int

    # void perf_buffer__free(struct perf_buffer *pb)
    lib.perf_buffer__free.argtypes = [ctypes.c_void_p]
    lib.perf_buffer__free.restype = None


# ============================================================
# event_t 结构体（与 eBPF C 代码中的定义一致）
# ============================================================

# 常量
EVENT_EXECVE = 0
EVENT_OPENAT = 1
EVENT_CONNECT = 2
FILENAME_MAX_LEN = 256
ARGV_MAX_LEN = 512
COMM_MAX_LEN = 16


class EventExec(ctypes.Structure):
    """execve 事件字段"""
    _fields_ = [
        ("filename", ctypes.c_char * FILENAME_MAX_LEN),
        ("argv", ctypes.c_char * ARGV_MAX_LEN),
    ]


class EventFile(ctypes.Structure):
    """openat 事件字段"""
    _fields_ = [
        ("filename", ctypes.c_char * FILENAME_MAX_LEN),
        ("flags", ctypes.c_uint32),
    ]


class EventNet(ctypes.Structure):
    """connect 事件字段"""
    _fields_ = [
        ("ip_addr", ctypes.c_uint32),
        ("port", ctypes.c_uint16),
        ("protocol", ctypes.c_uint8),
    ]


class EventUnion(ctypes.Union):
    """事件联合体"""
    _fields_ = [
        ("exec", EventExec),
        ("file", EventFile),
        ("net", EventNet),
    ]


class EventT(ctypes.Structure):
    """
    与 observer.bpf.c 中的 struct event_t 完全一致。
    用于从 perf ring buffer 解析事件数据。
    """
    _fields_ = [
        ("timestamp_ns", ctypes.c_uint64),
        ("pid", ctypes.c_uint32),
        ("ppid", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("event_type", ctypes.c_uint8),
        ("blocked", ctypes.c_uint8),
        ("padding", ctypes.c_uint16),
        ("data", EventUnion),
        ("comm", ctypes.c_char * COMM_MAX_LEN),
    ]


# ============================================================
# EbpfCollector 实现
# ============================================================

class EbpfCollector(ICollector):
    """
    eBPF 采集器 —— 加载 eBPF 字节码，挂载 tracepoint 探针，
    消费 perf ring buffer 事件并转换为 RawEvent。

    第一版仅做观测，不支持阻断。
    """

    def __init__(self, config: dict):
        """
        初始化 eBPF 采集器。

        参数:
            config: 配置字典（从 config.yaml 加载）
        """
        self.config = config
        self.ebpf_config = config.get("ebpf", {})
        self.bpf_object_path = self.ebpf_config.get(
            "bpf_object_path", "ebpf/observer.bpf.o")
        self.target_agent_id = self.ebpf_config.get(
            "target_agent_id", "observed-agent")
        self.perf_buffer_pages = self.ebpf_config.get(
            "perf_buffer_page_count", 64)

        # 内部状态
        self._lib = None
        self._bpf_object = None
        self._perf_buffer = None
        self._links = []  # bpf_link 列表
        self._event_queue = queue.Queue(maxsize=10000)
        self._poll_thread = None
        self._running = False
        self._seq = 0
        self._attached = False

        # 加载 libbpf
        try:
            self._lib = _load_libbpf()
            _setup_libbpf_signatures(self._lib)
        except ImportError:
            logger.error("libbpf 不可用，EbpfCollector 无法初始化")
            raise

    def capabilities(self) -> CollectorCapabilities:
        """返回 eBPF 采集器能力描述"""
        return CollectorCapabilities(
            name="Ebpf",
            can_observe=True,
            can_block_tier2=False,    # 第一版不支持
            can_block_tier3=False,    # 第一版不支持
            is_transparent=True,      # 对 Agent 无感知
            performance_overhead="low",
            time_source="realtime_monotonic",
        )

    def _libbpf_strerror(self, err: int) -> str:
        """将 libbpf 错误码转换为可读字符串"""
        buf = ctypes.create_string_buffer(256)
        try:
            self._lib.libbpf_strerror(err, buf, 256)
            return buf.value.decode("utf-8", errors="replace")
        except Exception:
            return f"errno={err}"

    def attach(self, target_pid: int = 0, agent_id: str = "") -> bool:
        """
        加载 eBPF 程序并挂载到 tracepoint。

        参数:
            target_pid: 目标进程 PID（eBPF 模式下全局观测，此参数仅用于记录）
            agent_id:   Agent 标识（用于 RawEvent 的 agent_id 字段）

        返回:
            True: 加载并挂载成功
            False: 失败
        """
        if agent_id:
            self.target_agent_id = agent_id

        logger.info(f"[诊断] bpf_object_path = {os.path.abspath(self.bpf_object_path)}")
        logger.info(f"[诊断] 文件存在: {os.path.isfile(self.bpf_object_path)}")
        logger.info(f"[诊断] 文件大小: {os.path.getsize(self.bpf_object_path) if os.path.isfile(self.bpf_object_path) else 'N/A'} bytes")

        # 检查 .bpf.o 文件是否存在
        if not os.path.isfile(self.bpf_object_path):
            logger.error(f"eBPF 字节码文件不存在: {self.bpf_object_path}")
            return False

        try:
            # 1. 打开 eBPF 对象
            bpf_path_bytes = self.bpf_object_path.encode("utf-8")
            logger.info(f"[诊断] 调用 bpf_object__open(\"{self.bpf_object_path}\")")
            self._bpf_object = self._lib.bpf_object__open(bpf_path_bytes)
            if not self._bpf_object:
                logger.error(f"[诊断] bpf_object__open 返回 NULL (0x0)")
                return False
            logger.info(f"[诊断] bpf_object__open 成功: ptr=0x{self._bpf_object:x}")

            # 2. 加载 eBPF 程序到内核
            logger.info("[诊断] 调用 bpf_object__load ...")
            ret = self._lib.bpf_object__load(self._bpf_object)
            if ret != 0:
                err_str = self._libbpf_strerror(ret)
                logger.error(f"[诊断] bpf_object__load 失败: ret={ret}, {err_str}")
                self._cleanup()
                return False
            logger.info("[诊断] bpf_object__load 成功 (ret=0)")

            # 3. 挂载三个 tracepoint 探针
            probe_names = [
                b"tracepoint__syscalls__sys_enter_execve",
                b"tracepoint__syscalls__sys_enter_openat",
                b"tracepoint__syscalls__sys_enter_connect",
            ]

            for name in probe_names:
                prog = self._lib.bpf_object__find_program_by_name(
                    self._bpf_object, name)
                if not prog:
                    logger.error(f"[诊断] bpf_object__find_program_by_name(\"{name.decode()}\") 返回 NULL")
                    self._cleanup()
                    return False

                fd = self._lib.bpf_program__fd(prog)
                logger.info(f"[诊断] 探针 {name.decode()}: prog=0x{prog:x}, fd={fd}")

                link = self._lib.bpf_program__attach(prog)
                if not link:
                    logger.error(f"[诊断] bpf_program__attach(\"{name.decode()}\") 返回 NULL")
                    self._cleanup()
                    return False

                self._links.append(link)
                logger.info(f"[诊断] 探针已挂载: {name.decode()} (link=0x{link:x})")

            # 4. 设置 perf ring buffer
            logger.info("[诊断] 调用 bpf_object__find_map_fd_by_name(\"events\")")
            events_map_fd = self._lib.bpf_object__find_map_fd_by_name(
                self._bpf_object, b"events")
            logger.info(f"[诊断] events map fd = {events_map_fd}")
            if events_map_fd < 0:
                logger.error(f"[诊断] events map 查找失败: fd={events_map_fd}")
                self._cleanup()
                return False

            # 创建 perf buffer
            self._perf_buffer = self._setup_perf_buffer(events_map_fd)
            if not self._perf_buffer:
                logger.error("[诊断] perf buffer 创建失败 (返回 NULL/0)")
                self._cleanup()
                return False
            logger.info(f"[诊断] perf_buffer 创建成功: ptr=0x{self._perf_buffer:x}")

            self._attached = True
            self._running = True

            # 5. 启动轮询线程
            self._poll_thread = threading.Thread(
                target=self._poll_loop, daemon=True, name="ebpf-poll")
            self._poll_thread.start()

            # 6. 注册退出清理
            atexit.register(self.detach)

            logger.info(
                f"EbpfCollector 已附着 (agent_id={self.target_agent_id})")
            return True

        except Exception as e:
            logger.error(f"[诊断] EbpfCollector attach 异常: {type(e).__name__}: {e}")
            import traceback
            logger.error(traceback.format_exc())
            self._cleanup()
            return False

    def _setup_perf_buffer(self, map_fd: int):
        """
        创建 perf ring buffer。

        使用 perf_buffer__new API（libbpf >= 0.8）直接传入回调函数。
        """
        # 定义回调类型
        # typedef void (*perf_buffer_sample_fn)(void *ctx, int cpu,
        #                                      void *data, __u32 size);
        SAMPLE_CB = ctypes.CFUNCTYPE(
            None, ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32)
        # typedef void (*perf_buffer_lost_fn)(void *ctx, int cpu, __u64 cnt);
        LOST_CB = ctypes.CFUNCTYPE(
            None, ctypes.c_void_p, ctypes.c_int, ctypes.c_uint64)

        def sample_callback(ctx, cpu, data, size):
            """perf buffer 事件回调"""
            if size < ctypes.sizeof(EventT):
                return
            event_data = ctypes.string_at(data, size)
            try:
                self._event_queue.put_nowait(event_data)
            except queue.Full:
                logger.warning("事件队列已满，丢弃事件")

        def lost_callback(ctx, cpu, lost_cnt):
            """perf buffer 事件丢失回调"""
            logger.warning(f"CPU {cpu}: 丢失 {lost_cnt} 个事件")

        # 保存回调引用防止被 GC 回收（关键！）
        self._sample_cb = SAMPLE_CB(sample_callback)
        self._lost_cb = LOST_CB(lost_callback)

        logger.info(f"[诊断] perf_buffer__new: map_fd={map_fd}, "
                     f"page_cnt={self.perf_buffer_pages}, "
                     f"sample_cb=0x{ctypes.cast(self._sample_cb, ctypes.c_void_p).value:x}, "
                     f"lost_cb=0x{ctypes.cast(self._lost_cb, ctypes.c_void_p).value:x}")

        try:
            # 优先使用 perf_buffer__new（libbpf >= 0.8）
            pb = self._lib.perf_buffer__new(
                map_fd,
                self.perf_buffer_pages,
                self._sample_cb,   # sample_cb
                self._lost_cb,     # lost_cb
                None,              # ctx
                None               # opts (NULL = 默认)
            )
            logger.info(f"[诊断] perf_buffer__new 返回: {pb:#x}" if pb else "[诊断] perf_buffer__new 返回 NULL")
            return pb
        except AttributeError:
            # perf_buffer__new 不存在，尝试旧版 perf_buffer__new_raw
            logger.warning("[诊断] perf_buffer__new 不可用，尝试 perf_buffer__new_raw")
            try:
                pb = self._lib.perf_buffer__new_raw(
                    map_fd, self.perf_buffer_pages, None)
                return pb
            except Exception as e2:
                logger.error(f"[诊断] perf_buffer__new_raw 也失败: {e2}")
                return None
        except Exception as e:
            logger.error(f"[诊断] perf_buffer__new 异常: {type(e).__name__}: {e}")
            return None

    def _poll_loop(self):
        """perf buffer 轮询线程"""
        while self._running and self._perf_buffer:
            try:
                ret = self._lib.perf_buffer__poll(self._perf_buffer, 100)
                if ret < 0:
                    logger.warning(f"perf_buffer__poll 返回错误: {ret}")
                    break
            except Exception as e:
                if self._running:
                    logger.error(f"poll loop 异常: {e}")
                break

    def _to_raw_event(self, event_data: bytes) -> Optional[RawEvent]:
        """
        将 event_t 字节数据转换为 RawEvent。

        按照定稿 §3.3 字段映射表进行转换。

        参数:
            event_data: perf buffer 返回的原始字节数据

        返回:
            RawEvent 对象，解析失败返回 None
        """
        try:
            event = EventT()
            ctypes.memmove(ctypes.byref(event), event_data,
                           min(len(event_data), ctypes.sizeof(event)))

            self._seq += 1
            event_id = f"ebpf_evt_{self._seq:06d}"

            # 公共字段映射
            raw = RawEvent(
                event_id=event_id,
                timestamp_ns=event.timestamp_ns,
                event_type="",  # 下面根据类型设置
                pid=event.pid,
                ppid=event.ppid,
                agent_id=self.target_agent_id,
                agent_framework="ebpf",
            )

            # 根据 event_type 映射特定字段
            if event.event_type == EVENT_EXECVE:
                raw.event_type = "exec"
                raw.executable = event.data.exec.filename.decode(
                    "utf-8", errors="replace").rstrip("\x00")

                # 解析 argv（\0 分隔的字符串）
                # ctypes 读取 c_char 数组只到第一个 \0，需要用 memmove 读取完整缓冲区
                argv_buf = ctypes.create_string_buffer(ARGV_MAX_LEN)
                argv_src = ctypes.addressof(event) + EventT.data.offset + EventUnion.exec.offset + EventExec.argv.offset
                ctypes.memmove(argv_buf, argv_src, ARGV_MAX_LEN)
                argv_str = argv_buf.raw.decode("utf-8", errors="replace")
                arguments = [a for a in argv_str.split("\x00") if a]
                raw.arguments = arguments if arguments else None

            elif event.event_type == EVENT_OPENAT:
                raw.event_type = "file_open"
                raw.file_path = event.data.file.filename.decode(
                    "utf-8", errors="replace").rstrip("\x00")

                # flags 映射: O_RDONLY=0, O_WRONLY=1, O_RDWR=2
                flags = event.data.file.flags
                if flags & 0x2:  # O_RDWR
                    raw.file_op = "write"
                elif flags & 0x1:  # O_WRONLY
                    raw.file_op = "write"
                else:
                    raw.file_op = "read"

            elif event.event_type == EVENT_CONNECT:
                raw.event_type = "net_conn"
                # IP 地址转换（网络字节序 → 点分十进制）
                ip_bytes = struct.pack("!I", event.data.net.ip_addr)
                raw.remote_addr = socket.inet_ntoa(ip_bytes)
                # 端口转换（网络字节序 → 主机字节序）
                raw.remote_port = socket.ntohs(event.data.net.port)
                # 协议映射
                raw.protocol = "TCP" if event.data.net.protocol == 0 else "UDP"

            else:
                logger.warning(f"未知事件类型: {event.event_type}")
                return None

            return raw

        except Exception as e:
            logger.error(f"事件转换失败: {e}")
            return None

    def start(self) -> Iterator[RawEvent]:
        """
        开始采集，返回 RawEvent 生成器。

        从 perf ring buffer 队列中读取事件并转换为 RawEvent yield。
        """
        if not self._attached:
            logger.warning("EbpfCollector 未附着，请先调用 attach()")
            return

        while self._running:
            try:
                event_data = self._event_queue.get(timeout=1.0)
                raw = self._to_raw_event(event_data)
                if raw:
                    yield raw
            except queue.Empty:
                continue

    def send_command(self, cmd) -> bool:
        """
        eBPF 第一版不支持阻断。

        返回 False 并记录警告日志。
        """
        logger.warning(
            "eBPF 第一版不支持阻断，send_command() 忽略。"
            "阻断功能将在第二版实现（kprobe + bpf_override_return）")
        return False

    def detach(self) -> None:
        """断开采集，清理 eBPF 资源"""
        self._running = False
        self._cleanup()
        self._attached = False
        logger.info("EbpfCollector 已断开")

    def _cleanup(self):
        """清理所有 eBPF 资源"""
        if self._poll_thread and self._poll_thread.is_alive():
            self._running = False
            self._poll_thread.join(timeout=2.0)

        if self._perf_buffer and self._lib:
            try:
                self._lib.perf_buffer__free(self._perf_buffer)
            except Exception:
                pass
            self._perf_buffer = None

        if self._links and self._lib:
            for link in self._links:
                try:
                    self._lib.bpf_link__destroy(link)
                except Exception:
                    pass
            self._links.clear()

        if self._bpf_object and self._lib:
            try:
                self._lib.bpf_object__close(self._bpf_object)
            except Exception:
                pass
            self._bpf_object = None

    def get_process_tree(self) -> dict:
        """
        获取进程树快照。

        eBPF 模式下从 /proc 构建目标进程的进程树。
        第一版简化实现，返回空字典。
        """
        # TODO: 从 /proc/{pid}/stat 构建进程树
        return {}
