@echo off
REM pkg-config shim entry: CMake's FindPkgConfig calls "pkg-config".
REM Forward to the Python implementation in this directory.
python "%~dp0pkgconfig_shim.py" %*
