"""Windows GUI smoke test; no credentials or campus-network access required."""
import ctypes
from ctypes import wintypes
import pathlib
import subprocess
import sys
import tempfile
import time

user32 = ctypes.WinDLL("user32", use_last_error=True)
CALLBACK = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
user32.EnumWindows.argtypes = [CALLBACK, wintypes.LPARAM]
user32.EnumChildWindows.argtypes = [wintypes.HWND, CALLBACK, wintypes.LPARAM]
user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
user32.IsWindowVisible.argtypes = [wintypes.HWND]
user32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
user32.FindWindowW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR]
user32.FindWindowW.restype = wintypes.HWND
user32.SendMessageTimeoutW.argtypes = [
    wintypes.HWND, wintypes.UINT, wintypes.WPARAM, ctypes.c_size_t,
    wintypes.UINT, wintypes.UINT, ctypes.POINTER(ctypes.c_size_t),
]
user32.SendMessageTimeoutW.restype = wintypes.LPARAM
TRAY_MESSAGE = 0x8000 + 20
# GetWindowTextW 读不到其他进程里控件的文本（对子控件一律返回空串），
# 只能取到顶层窗口标题。WM_GETTEXT 属于系统消息，系统会帮我们跨进程传递缓冲区。
WM_GETTEXT = 0x000D
SMTO_ABORTIFHUNG = 0x0002
MESSAGE_TIMEOUT_MS = 2000


def wait_until(check, description, timeout=20):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = check()
        if result:
            return result
        time.sleep(0.1)
    raise AssertionError(f"Timed out: {description}")


def text(hwnd):
    value = ctypes.create_unicode_buffer(1_000_000)
    result = ctypes.c_size_t()
    # 带超时，避免目标进程无响应时把测试挂死。
    user32.SendMessageTimeoutW(
        hwnd, WM_GETTEXT, len(value), ctypes.addressof(value),
        SMTO_ABORTIFHUNG, MESSAGE_TIMEOUT_MS, ctypes.byref(result),
    )
    return value.value


def window_for(process):
    found = []

    @CALLBACK
    def collect(hwnd, _):
        pid = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        if pid.value == process.pid and "v1.0.0" in text(hwnd):
            found.append(hwnd)
        return True

    user32.EnumWindows(collect, 0)
    return found[0] if found else None


def children(hwnd):
    found = []

    @CALLBACK
    def collect(child, _):
        found.append((child, text(child)))
        return True

    user32.EnumChildWindows(hwnd, collect, 0)
    return found


def post(hwnd, message, w=0, l=0):
    assert user32.PostMessageW(hwnd, message, w, l), ctypes.get_last_error()


def quit_app(process, hwnd):
    button = next(child for child, label in children(hwnd) if label == "退出")
    post(button, 0x00F5)  # BM_CLICK
    assert process.wait(timeout=25) == 0


def exercise(exe, config, minimized=False, missing=False):
    args = [str(exe), "--config", str(config)]
    if minimized:
        args.append("--minimized")
    process = subprocess.Popen(args)
    try:
        hwnd = wait_until(lambda: window_for(process), "GUI window creation")
        if missing:
            wait_until(lambda: any("启动失败" in label for _, label in children(hwnd)), "visible config error")
            assert user32.IsWindowVisible(hwnd), "Configuration errors must restore the window"
        else:
            wait_until(lambda: any("启动了喵" in label for _, label in children(hwnd)), "worker logs")
            shell_available = bool(user32.FindWindowW("Shell_TrayWnd", None))
            if shell_available:
                if minimized:
                    wait_until(lambda: not user32.IsWindowVisible(hwnd), "start minimized")
                else:
                    assert user32.IsWindowVisible(hwnd)
                    post(hwnd, 0x0010)  # WM_CLOSE must hide, not exit
                    wait_until(lambda: not user32.IsWindowVisible(hwnd), "close hides to tray")
                assert process.poll() is None
                # Exercise the same callback as a shell-delivered tray double click.
                # This does not constitute a physical click/visual test of Explorer's icon.
                post(hwnd, TRAY_MESSAGE, 1, 0x0203)
                wait_until(lambda: user32.IsWindowVisible(hwnd), "tray callback restores window")
                post(hwnd, 0x0112, 0xF020)  # WM_SYSCOMMAND / SC_MINIMIZE
                wait_until(lambda: not user32.IsWindowVisible(hwnd), "minimize hides to tray")
                post(hwnd, TRAY_MESSAGE, 1, 0x0203)
                wait_until(lambda: user32.IsWindowVisible(hwnd), "second restore")
                print("PASS: hide, restore, minimize, restore; process remains running")
            else:
                wait_until(lambda: user32.IsWindowVisible(hwnd), "no-tray fallback stays visible")
                post(hwnd, 0x0010)
                time.sleep(0.3)
                assert user32.IsWindowVisible(hwnd)
                print("SKIP: Explorer tray unavailable; verified visible fallback instead")
        quit_app(process, hwnd)
        print(f"PASS: clean exit (minimized={minimized}, missing_config={missing})")
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()


def main():
    exe = pathlib.Path(sys.argv[1]).resolve()
    result = subprocess.run([str(exe), "--help"], capture_output=True, timeout=10)
    assert result.returncode == 0 and b"--minimized" in result.stdout
    with tempfile.TemporaryDirectory(prefix="yzu-smoke-") as directory:
        config = pathlib.Path(directory) / "config.toml"
        config.write_text('user_id = "ci-test-user"\npassword = "ci-test-password"\nservice_index = 1\ninterval_secs = 600\n', encoding="utf-8")
        exercise(exe, config)
        exercise(exe, config, minimized=True)
        exercise(exe, pathlib.Path(directory) / "missing.toml", minimized=True, missing=True)
        result = subprocess.run([str(exe), "--once", "--config", str(config)], capture_output=True, timeout=30)
        assert result.returncode == 0 and "启动了喵".encode() in result.stdout
        result = subprocess.run([str(exe), "--once", "--config", str(config.parent / "missing.toml")], capture_output=True, timeout=10)
        assert result.returncode == 1
        print("PASS: console help, --once and configuration error exit code")


if __name__ == "__main__":
    main()
