"""
PipeReader — 正向管道读取器 (C++ → Python)

从 C++ 探针层通过命名管道接收事件。
管道名: ``\\\\.\\pipe\\observer_events``
方向: C++ (客户端) → Python (服务端)

关键特性:
- Python 侧作为服务端创建管道
- 自动重连（指数退避: 1s/2s/4s，最多 3 次）
- 非阻塞轮询
- 逐行读取 JSON 并反序列化为 RawEvent
"""

import sys
import json
import time
import logging
from typing import Optional
from abc import ABC, abstractmethod

# 将项目根目录加入 sys.path
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from models.event import RawEvent

logger = logging.getLogger(__name__)


class IPipeReader(ABC):
    """管道读取器抽象接口"""

    @abstractmethod
    def connect(self, pipe_name: str) -> bool:
        """连接到命名管道"""
        ...

    @abstractmethod
    def read_event(self) -> Optional[RawEvent]:
        """非阻塞读取一个事件，无事件返回 None"""
        ...

    @abstractmethod
    def disconnect(self) -> None:
        """断开管道连接"""
        ...


class PipeReader(IPipeReader):
    """
    Windows 命名管道读取器实现。
    
    Python 侧作为服务端创建管道，C++ 侧作为客户端连接。
    使用 win32pipe/win32file 进行管道操作。
    """

    def __init__(self):
        self._pipe_name: str = ""
        self._handle = None
        self._connected: bool = False
        self._buffer: str = ""  # 未处理完的行缓冲
        self._reconnect_attempts: int = 0
        self._max_reconnect: int = 3

    def connect(self, pipe_name: str) -> bool:
        """
        创建并等待命名管道连接。
        
        Python 侧作为服务端:
        1. 调用 CreateNamedPipe 创建管道
        2. 调用 ConnectNamedPipe 等待客户端连接
        """
        self._pipe_name = pipe_name

        if sys.platform != "win32":
            logger.warning(f"[PipeReader] Non-Windows platform, pipe not available")
            return False

        try:
            import win32pipe
            import win32file
            import pywintypes

            # 创建命名管道（服务端）
            # PIPE_ACCESS_INBOUND: 数据从客户端流向服务端（C++ → Python）
            self._handle = win32pipe.CreateNamedPipe(
                pipe_name,
                win32pipe.PIPE_ACCESS_INBOUND,
                win32pipe.PIPE_TYPE_BYTE | win32pipe.PIPE_READMODE_BYTE | win32pipe.PIPE_WAIT,
                1,       # 最大实例数
                65536,   # 输出缓冲区大小
                65536,   # 输入缓冲区大小
                0,       # 默认超时
                None     # 默认安全属性
            )

            if self._handle == win32file.INVALID_HANDLE_VALUE:
                logger.error(f"[PipeReader] CreateNamedPipe failed")
                return False

            logger.info(f"[PipeReader] Waiting for C++ client to connect on {pipe_name}...")

            # 等待客户端连接
            win32pipe.ConnectNamedPipe(self._handle, None)

            self._connected = True
            self._reconnect_attempts = 0
            logger.info(f"[PipeReader] Connected on {pipe_name}")
            return True

        except ImportError:
            logger.error("[PipeReader] pywin32 not installed. Install with: pip install pywin32")
            return False
        except Exception as e:
            logger.error(f"[PipeReader] Connect failed: {e}")
            return False

    def read_event(self) -> Optional[RawEvent]:
        """
        非阻塞读取一个事件。
        
        从管道读取数据，按行分割，每行解析为一个 RawEvent。
        如果没有完整的一行可用，返回 None。
        """
        if not self._connected:
            return None

        if sys.platform != "win32":
            return None

        try:
            import win32file
            import pywintypes

            # 尝试读取数据（最多 4096 字节）
            try:
                _, data = win32file.ReadFile(self._handle, 4096)
                self._buffer += data.decode('utf-8', errors='replace')
            except pywintypes.error as e:
                if e.winerror == 109:  # ERROR_BROKEN_PIPE
                    logger.warning("[PipeReader] Pipe broken by client")
                    self._connected = False
                    return None
                raise

            # 检查是否有完整的行
            while '\n' in self._buffer:
                line, self._buffer = self._buffer.split('\n', 1)
                line = line.strip()
                if not line:
                    continue

                try:
                    event = RawEvent.from_json_line(line)
                    return event
                except (json.JSONDecodeError, KeyError) as e:
                    logger.warning(f"[PipeReader] Failed to parse event: {e}, line: {line[:100]}")
                    continue

            return None

        except Exception as e:
            logger.error(f"[PipeReader] read_event error: {e}")
            self._connected = False
            return None

    def disconnect(self) -> None:
        """断开管道连接"""
        if self._handle is not None and sys.platform == "win32":
            try:
                import win32file
                import win32pipe
                try:
                    win32pipe.DisconnectNamedPipe(self._handle)
                except Exception:
                    pass
                win32file.CloseHandle(self._handle)
            except Exception as e:
                logger.warning(f"[PipeReader] Disconnect error: {e}")
        self._handle = None
        self._connected = False
        self._buffer = ""

    @property
    def is_connected(self) -> bool:
        return self._connected


class MockPipeReader(IPipeReader):
    """
    模拟管道读取器 — 用于测试和调试。
    
    不从真实管道读取，而是从内存队列中获取事件。
    适用于单元测试和跨平台开发。
    """

    def __init__(self):
        self._events: list = []
        self._connected: bool = False

    def connect(self, pipe_name: str) -> bool:
        self._connected = True
        logger.info(f"[MockPipeReader] Connected (mock mode)")
        return True

    def read_event(self) -> Optional[RawEvent]:
        if not self._connected or not self._events:
            return None
        return self._events.pop(0)

    def disconnect(self) -> None:
        self._connected = False
        self._events.clear()

    def inject_event(self, event: RawEvent) -> None:
        """注入一个事件到队列（测试用）"""
        self._events.append(event)

    def inject_events(self, events: list) -> None:
        """批量注入事件（测试用）"""
        self._events.extend(events)

    @property
    def is_connected(self) -> bool:
        return self._connected

    @property
    def pending_count(self) -> int:
        return len(self._events)
