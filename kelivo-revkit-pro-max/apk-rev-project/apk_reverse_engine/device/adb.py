"""设备集成 - ADB 真机/模拟器操作

参照 Operit 设备集成能力：
- 连接/断开 Android 设备
- 安装/卸载 APK
- 拉取/推送文件
- 截图/录屏
- 获取设备信息
"""
import subprocess, json, os, re, time


class ADB:
    """Android Debug Bridge 封装"""

    def __init__(self, device_id=None):
        self.device_id = device_id

    # ---- 设备管理 ----
    @staticmethod
    def devices():
        r = _run('adb devices -l')
        out = []
        for line in r.splitlines():
            if '\tdevice' in line:
                parts = line.split()
                out.append({'id': parts[0], 'desc': ' '.join(parts[2:]) if len(parts) > 2 else ''})
        return out

    def connect(self, host='127.0.0.1', port=5555):
        return _run(f'adb connect {host}:{port}')

    def disconnect(self):
        cmd = f'adb disconnect {self.device_id}' if self.device_id else 'adb disconnect'
        return _run(cmd)

    def info(self):
        """获取设备信息"""
        d = self.device_id or ''
        return {
            'device': self.device_id,
            'model': _run(f'adb {d} shell getprop ro.product.model').strip(),
            'android': _run(f'adb {d} shell getprop ro.build.version.release').strip(),
            'sdk': _run(f'adb {d} shell getprop ro.build.version.sdk').strip(),
            'manufacturer': _run(f'adb {d} shell getprop ro.product.manufacturer').strip(),
            'abi': _run(f'adb {d} shell getprop ro.product.cpu.abi').strip(),
            'battery': _run(f'adb {d} shell dumpsys battery | grep level').strip(),
        }

    # ---- APK 操作 ----
    def install(self, apk_path, reinstall=False, grant_permissions=False):
        cmd = f'adb {self._pre} install'
        if reinstall:
            cmd += ' -r'
        if grant_permissions:
            cmd += ' -g'
        cmd += f' {apk_path}'
        return _run(cmd)

    def uninstall(self, package_name, keep_data=False):
        cmd = f'adb {self._pre} uninstall'
        if keep_data:
            cmd += ' -k'
        cmd += f' {package_name}'
        return _run(cmd)

    def launch(self, package_name, activity=None):
        if activity:
            return _run(f'adb {self._pre} shell am start -n {package_name}/{activity}')
        # 自动获取 launcher activity
        out = _run(f'adb {self._pre} shell pm resolve-activity --brief {package_name}')
        activity = out.strip().split('/')[-1] if '/' in out else ''
        return _run(f'adb {self._pre} shell am start -n {package_name}/{activity}')

    def force_stop(self, package_name):
        return _run(f'adb {self._pre} shell am force-stop {package_name}')

    def list_packages(self, filter_str=None, third_party=True):
        cmd = f'adb {self._pre} shell pm list packages'
        if third_party:
            cmd += ' -3'
        if filter_str:
            cmd += f' | grep {filter_str}'
        return sorted(set(_run(cmd).replace('package:', '').splitlines()))

    # ---- 文件操作 ----
    def pull(self, remote, local):
        return _run(f'adb {self._pre} pull {remote} {local}')

    def push(self, local, remote):
        return _run(f'adb {self._pre} push {local} {remote}')

    def screenshot(self, output_path):
        """截图并保存到本地"""
        _run(f'adb {self._pre} shell screencap -p /sdcard/screen_tmp.png')
        self.pull('/sdcard/screen_tmp.png', output_path)
        _run(f'adb {self._pre} shell rm /sdcard/screen_tmp.png')
        return output_path

    # ---- 日志 ----
    def logcat(self, filter_spec=None, lines=50):
        cmd = f'adb {self._pre} logcat -d'
        if filter_spec:
            cmd += f' -s {filter_spec}'
        cmd += f' -t {lines}'
        return _run(cmd)

    def clear_logcat(self):
        return _run(f'adb {self._pre} logcat -c')

    # ---- 键盘/输入 ----
    def tap(self, x, y):
        return _run(f'adb {self._pre} shell input tap {x} {y}')

    def swipe(self, x1, y1, x2, y2, duration_ms=300):
        return _run(f'adb {self._pre} shell input swipe {x1} {y1} {x2} {y2} {duration_ms}')

    def text(self, content):
        return _run(f'adb {self._pre} shell input text {_shell_escape(content)}')

    def keyevent(self, keycode):
        return _run(f'adb {self._pre} shell input keyevent {keycode}')

    # ---- 内部 ----
    @property
    def _pre(self):
        return f'-s {self.device_id}' if self.device_id else ''

    def __repr__(self):
        return f'<ADB device={self.device_id}>'


def _run(cmd, timeout=30):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        if r.returncode != 0:
            raise RuntimeError(f'ADB 错误: {r.stderr.strip() or r.stdout.strip()}')
        return r.stdout.strip()
    except FileNotFoundError:
        raise RuntimeError('PATH 中未找到 adb, 请安装 Android SDK platform-tools')


def _shell_escape(s):
    return s.replace(' ', '%s').replace('"', '\\"').replace("'", "\\'")