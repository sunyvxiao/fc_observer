cmake_minimum_required(VERSION 3.15)
project(observer_probe VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 探针层可执行文件
# 注意: process_probe.h, file_probe.h, network_probe.h, event_formatter.h
# 均为 header-only 实现，不需要额外的 .cpp 文件
add_executable(cpp_probe
    main.cpp
    process_table.cpp
)

# 包含当前目录（头文件搜索路径）
target_include_directories(cpp_probe PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

# Windows 特定设置
if(WIN32)
    # 链接 Win32 命名管道所需的库
    target_link_libraries(cpp_probe PRIVATE)
    # 定义 UNICODE 宏
    target_compile_definitions(cpp_probe PRIVATE _WIN32_WINNT=0x0601)
endif()

# 输出目录设置
set_target_properties(cpp_probe PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)
