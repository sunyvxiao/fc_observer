"""
CommandSender — 反向管道指令发送器 (Python → C++)

通过命名管道向 C++ 探针层发送阻断指令。
管道名: ``\\\\.\\pipe\\observer_commands``
方向: Python (服务端) → C++ (客户端)

关键特性:
- Python 侧作为服务端创建管道
- 非阻塞写入
- 支持 allow/block_event/terminate_process/heartbeat 四种指令类型
- 管道断开时降级处理
"""

import sys
import json
import logging
from typing import Optional
from abc import ABC, abstractmethod

import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from models.command import Command, CmdType

logger = logging.getLogger(__name__)


class ICommandSender(ABC):
    """指令发送器抽象接口"""

    @abstractmethod
    def connect(self, pipe_name: str) -> bool:
        ...

    @abstractmethod
    def send_command(self, cmd: Command) -> bool:
        ...

    @abstractmethod
    def disconnect(self) -> None:
        ...


class CommandSender(ICommandSender):
    """
    Windows 命名管道指令发送器实现。
    
    Python 侧作为服务端创建管道，C++ 侧作为客户端连接。
    """

    def __init__(self):
        self._pipe_name: str = ""
        self._handle = None
        self._connected: bool = False
        self._cmd_counter: int = 0

    def connect(self, pipe_name: str) -> bool:
        """
        创建并等待命名管道连接。
        
        Python 侧作为服务端:
        1. 调用 CreateNamedPipe 创建管道
        2. 调用 ConnectNamedPipe 等待客户端连接
        """
        self._pipe_name = pipe_name

        if sys.platform != "win32":
            logger.warning(f"[CommandSender] Non-Windows platform, pipe not available")
            return False

        try:
            import win32pipe
            import win32file
            import pywintypes

            # 创建命名管道（服务端）
            # PIPE_ACCESS_OUTBOUND: 数据从服务端流向客户端（Python → C++）
            self._handle = win32pipe.CreateNamedPipe(
                pipe_name,
                win32pipe.PIPE_ACCESS_OUTBOUND,
                win32pipe.PIPE_TYPE_BYTE | win32pipe.PIPE_READMODE_BYTE | win32pipe.PIPE_WAIT,
                1,       # 最大实例数
                65536,   # 输出缓冲区大小
                65536,   # 输入缓冲区大小
                0,       # 默认超时
                None     # 默认安全属性
            )

            if self._handle == win32file.INVALID_HANDLE_VALUE:
                logger.error(f"[CommandSender] CreateNamedPipe failed")
                return False

            logger.info(f"[CommandSender] Waiting for C++ client to connect on {pipe_name}...")

            # 等待客户端连接
            win32pipe.ConnectNamedPipe(self._handle, None)

            self._connected = True
            logger.info(f"[CommandSender] Connected on {pipe_name}")
            return True

        except ImportError:
            logger.error("[CommandSender] pywin32 not installed. Install with: pip install pywin32")
            return False
        except Exception as e:
            logger.error(f"[CommandSender] Connect failed: {e}")
            return False

    def send_command(self, cmd: Command) -> bool:
        """
        发送阻断指令到 C++ 探针层。
        
        @param cmd: 要发送的指令
        @return: 是否成功发送
        """
        if not self._connected:
            logger.warning("[CommandSender] Not connected, command dropped")
            return False

        if sys.platform != "win32":
            return False

        try:
            import win32file
            import pywintypes

            json_line = cmd.to_json_line() + "\n"
            data = json_line.encode('utf-8')

            try:
                win32file.WriteFile(self._handle, data)
                logger.debug(f"[CommandSender] Sent: {cmd.cmd_type} -> {cmd.target_event_id or cmd.target_pid}")
                return True
            except pywintypes.error as e:
                if e.winerror == 109:  # ERROR_BROKEN_PIPE
                    logger.warning("[CommandSender] Pipe broken")
                    self._connected = False
                else:
                    logger.error(f"[CommandSender] WriteFile failed: {e}")
                return False

        except Exception as e:
            logger.error(f"[CommandSender] send_command error: {e}")
            self._connected = False
            return False

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
                logger.warning(f"[CommandSender] Disconnect error: {e}")
        self._handle = None
        self._connected = False

    @property
    def is_connected(self) -> bool:
        return self._connected

    def next_cmd_id(self) -> str:
        """生成下一个指令 ID"""
        self._cmd_counter += 1
        return f"cmd_{self._cmd_counter:04d}"


class MockCommandSender(ICommandSender):
    """
    模拟指令发送器 — 用于测试和调试。
    
    不发送到真实管道，而是将指令记录到内存列表。
    适用于单元测试和跨平台开发。
    """

    def __init__(self):
        self._commands: list = []
        self._connected: bool = False
        self._cmd_counter: int = 0

    def connect(self, pipe_name: str) -> bool:
        self._connected = True
        logger.info(f"[MockCommandSender] Connected (mock mode)")
        return True

    def send_command(self, cmd: Command) -> bool:
        if not self._connected:
            return False
        self._commands.append(cmd)
        logger.debug(f"[MockCommandSender] Recorded: {cmd.cmd_type} -> {cmd.target_event_id}")
        return True

    def disconnect(self) -> None:
        self._connected = False
        self._commands.clear()

    @property
    def is_connected(self) -> bool:
        return self._connected

    @property
    def sent_commands(self) -> list:
        """获取已发送的指令列表（测试用）"""
        return list(self._commands)

    @property
    def last_command(self) -> Optional[Command]:
        """获取最后一条指令（测试用）"""
        return self._commands[-1] if self._commands else None

    def clear(self) -> None:
        """清空已记录的指令"""
        self._commands.clear()

    def next_cmd_id(self) -> str:
        self._cmd_counter += 1
        return f"cmd_{self._cmd_counter:04d}"
