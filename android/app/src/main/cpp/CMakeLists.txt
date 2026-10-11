cmake_minimum_required(VERSION 3.22.1)
project("termux_pty")

# 上游原样：工作区终端的 PTY 库（PtyJni.loadLibrary("termux_pty")）。
add_library(termux_pty SHARED termux_pty.cpp)
target_link_libraries(termux_pty log)

# SoLab 增量：签名兼容注入原生库（原包模式，arm64）在子目录里，
# 与 termux_pty 同属一个 CMake 工程 —— Gradle 每变体只认一个入口，
# 拆成两个入口会让其中一个静默不编译（2026-09-23 真机闪退根因）。
add_subdirectory(signature)
