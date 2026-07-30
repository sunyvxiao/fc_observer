"""
adapter/pipe_factory.py — 管道适配器工厂

屏蔽 Windows 命名管道与 Linux FIFO 的差异。
数据流主路径已改为 ICollector.start() 直接 yield RawEvent，
PipeAdapter 仅用于需要跨进程管道通信的辅助场景（如 C++ 探针控制通道）。
"""

import os
import sys
import logging

logger = logging.getLogger(__name__)


class PipeAdapter:
    """
    管道适配器基类 — 定义跨平台管道接口。

    子类:
    - WindowsPipeAdapter: Windows 命名管道 (\\\\.\\pipe\\xxx)
    - LinuxFifoAdapter:   Linux FIFO 文件 (/tmp/observer/xxx)
    """

    def __init__(self, config: dict):
        self.config = config

    def open_event_pipe(self, mode: str):
        """打开正向管道（探针 → Observer）"""
        raise NotImplementedError

    def open_command_pipe(self, mode: str):
        """打开反向管道（Observer → 探针）"""
        raise NotImplementedError

    def cleanup(self):
        """清理管道资源"""
        raise NotImplementedError

    @staticmethod
    def create(config: dict, platform: str = None) -> "PipeAdapter":
        """
        工厂方法: 根据平台创建对应的管道适配器。

        参数:
            config:   配置字典
            platform: "windows" | "linux" | None (自动检测)

        返回:
            WindowsPipeAdapter 或 LinuxFifoAdapter 实例
        """
        if platform is None:
            platform = "windows" if sys.platform == "win32" else "linux"

        if platform == "windows":
            return WindowsPipeAdapter(config)
        else:
            return LinuxFifoAdapter(config)


class WindowsPipeAdapter(PipeAdapter):
    """
    Windows 命名管道适配器。

    管道路径格式: \\\\.\\pipe\\observer_events / \\\\.\\pipe\\observer_commands
    """

    def __init__(self, config: dict):
        super().__init__(config)
        pipeline = config.get("pipeline", {})
        pipes = config.get("pipes", {})
        self.event_pipe_name = pipeline.get(
            "win_event_pipe",
            pipes.get("events", r"\\.\pipe\observer_events"))
        self.command_pipe_name = pipeline.get(
            "win_command_pipe",
            pipes.get("commands", r"\\.\pipe\observer_commands"))
        self.connect_timeout_ms = pipes.get("connect_timeout_ms", 5000)
        self._event_handle = None
        self._command_handle = None

    def open_event_pipe(self, mode: str = "read"):
        """打开正向管道"""
        import win32pipe
        import win32file
        logger.info(f"打开 Windows 命名管道: {self.event_pipe_name} (mode={mode})")
        try:
            self._event_handle = win32file.CreateFile(
                self.event_pipe_name,
                win32file.GENERIC_READ if mode == "read" else win32file.GENERIC_WRITE,
                0, None, win32file.OPEN_EXISTING, 0, None
            )
            return self._event_handle
        except Exception as e:
            logger.error(f"打开管道失败: {e}")
            raise

    def open_command_pipe(self, mode: str = "write"):
        """打开反向管道"""
        import win32pipe
        import win32file
        logger.info(f"打开 Windows 命名管道: {self.command_pipe_name} (mode={mode})")
        try:
            self._command_handle = win32file.CreateFile(
                self.command_pipe_name,
                win32file.GENERIC_READ if mode == "read" else win32file.GENERIC_WRITE,
                0, None, win32file.OPEN_EXISTING, 0, None
            )
            return self._command_handle
        except Exception as e:
            logger.error(f"打开管道失败: {e}")
            raise

    def cleanup(self):
        """清理管道句柄"""
        import win32file
        for name, handle in [("_event_handle", self._event_handle),
                              ("_command_handle", self._command_handle)]:
            if handle is not None:
                try:
                    win32file.CloseHandle(handle)
                except Exception:
                    pass
                setattr(self, name, None)
        logger.info("Windows 管道资源已清理")

    def __repr__(self):
        return f"WindowsPipeAdapter(event={self.event_pipe_name}, command={self.command_pipe_name})"


class LinuxFifoAdapter(PipeAdapter):
    """
    Linux FIFO 管道适配器。

    FIFO 路径格式: /tmp/observer/events / /tmp/observer/commands
    """

    def __init__(self, config: dict):
        super().__init__(config)
        pipeline = config.get("pipeline", {})
        self.event_fifo = pipeline.get("linux_event_fifo", "/tmp/observer/events")
        self.command_fifo = pipeline.get("linux_command_fifo", "/tmp/observer/commands")
        self._event_fd = None
        self._command_fd = None

    def _ensure_fifo_dir(self, path: str):
        """确保 FIFO 所在目录存在"""
        dir_path = os.path.dirname(path)
        os.makedirs(dir_path, exist_ok=True)

    def _create_fifo_if_needed(self, path: str):
        """创建 FIFO 文件（如不存在）"""
        self._ensure_fifo_dir(path)
        if not os.path.exists(path):
            os.mkfifo(path)
            logger.info(f"创建 FIFO: {path}")

    def open_event_pipe(self, mode: str = "read"):
        """打开正向 FIFO"""
        self._create_fifo_if_needed(self.event_fifo)
        flags = os.O_RDONLY if mode == "read" else os.O_WRONLY
        self._event_fd = os.open(self.event_fifo, flags | os.O_NONBLOCK)
        logger.info(f"打开 Linux FIFO: {self.event_fifo} (mode={mode})")
        return self._event_fd

    def open_command_pipe(self, mode: str = "write"):
        """打开反向 FIFO"""
        self._create_fifo_if_needed(self.command_fifo)
        flags = os.O_RDONLY if mode == "read" else os.O_WRONLY
        self._command_fd = os.open(self.command_fifo, flags | os.O_NONBLOCK)
        logger.info(f"打开 Linux FIFO: {self.command_fifo} (mode={mode})")
        return self._command_fd

    def cleanup(self):
        """清理 FIFO 文件描述符"""
        for name, fd in [("_event_fd", self._event_fd),
                          ("_command_fd", self._command_fd)]:
            if fd is not None:
                try:
                    os.close(fd)
                except Exception:
                    pass
                setattr(self, name, None)
        logger.info("Linux FIFO 资源已清理")

    def __repr__(self):
        return f"LinuxFifoAdapter(event={self.event_fifo}, command={self.command_fifo})"
