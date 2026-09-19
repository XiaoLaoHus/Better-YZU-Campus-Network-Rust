"""Exercise the egui UI through Windows UI Automation and real keyboard input.

No native child-control assumptions, real credentials, or campus access required.
All application state is isolated from the runner's/user's LocalAppData.
"""
import ctypes
from ctypes import wintypes
import hashlib
import os
import pathlib
import subprocess
import sys
import tempfile
import time
import tomllib
import urllib.request

from pywinauto import Desktop, keyboard
from pywinauto.uia_defines import NoPatternInterfaceError

user32 = ctypes.WinDLL("user32", use_last_error=True)
CALLBACK = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
user32.EnumWindows.argtypes = [CALLBACK, wintypes.LPARAM]
user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
user32.IsWindowVisible.argtypes = [wintypes.HWND]
user32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
user32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
user32.FindWindowW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR]
user32.FindWindowW.restype = wintypes.HWND
TRAY_MESSAGE = 0x8000 + 20
SCREENSHOTS = pathlib.Path("artifacts/windows-ui")


def wait_until(check, description, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = check()
        if result:
            return result
        time.sleep(0.15)
    raise AssertionError(f"Timed out: {description}")


def title(hwnd):
    value = ctypes.create_unicode_buffer(512)
    user32.GetWindowTextW(hwnd, value, len(value))
    return value.value


def window_for(process):
    assert process.poll() is None, f"App exited before window creation: {process.returncode}"
    found = []

    @CALLBACK
    def collect(hwnd, _):
        pid = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        if pid.value == process.pid and "扬州大学校园网 · v" in title(hwnd):
            found.append(hwnd)
        return True

    user32.EnumWindows(collect, 0)
    return found[0] if found else None


def controls(window):
    # AccessKit exposes egui widgets via UIA, not HWND child windows.
    return window.descendants()


def has_text(window, text):
    return any(text in control.element_info.name for control in controls(window))


def control_for(window, name, control_type):
    return next((control for control in controls(window)
                 if control.element_info.name == name
                 and control.element_info.control_type == control_type), None)


def click(window, name):
    button = wait_until(lambda: control_for(window, name, "Button"), f"button {name}")
    wait_until(button.is_enabled, f"enabled button {name}")
    try:
        button.invoke()
    except NoPatternInterfaceError:
        # 下拉框选项带选中态，accesskit 按 UIA 惯例对这类节点只暴露 Toggle
        # 而不给 Invoke（is_invocable 里明确排除了有选中态的节点）。Toggle
        # 内部仍投递 Action::Click，与读屏用户走的路径一致，不是绕过自动化。
        button.toggle()
    time.sleep(0.2)


def type_into(window, name, value):
    edit = wait_until(lambda: control_for(window, name, "Edit"), f"input {name}")
    edit.click_input()
    keyboard.send_keys("^a" + value, pause=0.03, with_spaces=True)


def post(hwnd, message, w=0, l=0):
    assert user32.PostMessageW(hwnd, message, w, l), ctypes.get_last_error()


def restore(hwnd):
    # Same shell callback as a tray double click. Does not claim a physical click
    # on Explorer's icon, which can be inside its overflow popup.
    post(hwnd, TRAY_MESSAGE, 1, 0x0203)
    wait_until(lambda: user32.IsWindowVisible(hwnd), "tray callback restores window")


def screenshot(window, name):
    SCREENSHOTS.mkdir(parents=True, exist_ok=True)
    window.capture_as_image().save(str(SCREENSHOTS / f"{name}.png"))


def check_notice(window, hwnd, state, first_run):
    if not first_run:
        wait_until(lambda: has_text(window, "保存并连接"), "configuration editor")
        assert not has_text(window, "测试版使用提示"), "Acknowledged notice must not reappear"
        return
    wait_until(lambda: has_text(window, "测试版使用提示"), "first-run beta notice")
    assert has_text(window, "2576381123") and has_text(window, "很多问题")
    assert user32.IsWindowVisible(hwnd), "First-run notice must override --minimized"
    assert not state.exists(), "State must not be saved before acknowledgement"
    assert not has_text(window, "启动了喵"), "Automatic connection must wait for acknowledgement"
    post(hwnd, 0x0010)  # Closing must not silently hide the unacknowledged notice.
    time.sleep(0.4)
    assert user32.IsWindowVisible(hwnd)
    screenshot(window, "first-run-notice")
    click(window, "我已了解")
    wait_until(state.exists, "persist beta acknowledgement")
    assert tomllib.loads(state.read_text(encoding="utf-8"))["beta_notice_acknowledged"] is True
    wait_until(lambda: not has_text(window, "测试版使用提示"), "dismiss beta notice")


def exercise(exe, config, env, *, minimized=False, missing=False, first_run=False):
    args = [str(exe), "--config", str(config)]
    if minimized:
        args.append("--minimized")
    state = pathlib.Path(env["LOCALAPPDATA"]) / "Better-YZU-Campus-Network" / "ui-state.toml"
    process = subprocess.Popen(args, env=env)
    window = None
    try:
        hwnd = wait_until(lambda: window_for(process), "GUI window creation")
        window = Desktop(backend="uia").window(handle=hwnd).wrapper_object()
        check_notice(window, hwnd, state, first_run)
        shell_available = bool(user32.FindWindowW("Shell_TrayWnd", None))
        if missing:
            wait_until(lambda: has_text(window, "欢迎使用"), "first-run configuration editor")
            assert user32.IsWindowVisible(hwnd), "Missing configuration must show editor"
            screenshot(window, "empty-editor")
            type_into(window, "学工号 / 账号", "ci-ui-user")
            type_into(window, "校园网密码", "ci-ui-password")
            service = wait_until(lambda: control_for(window, "网络服务", "ComboBox"), "service selector")
            service.click_input()
            click(window, "联通互联网服务")
            screenshot(window, "centered-inputs")
            click(window, "保存并连接")
            wait_until(config.exists, "save new configuration")
            saved = tomllib.loads(config.read_text(encoding="utf-8"))
            assert saved["user_id"] == "ci-ui-user" and saved["password"] == "ci-ui-password"
            assert saved["service_index"] == 2
            wait_until(lambda: has_text(window, "启动了喵"), "worker starts after save")
            click(window, "停止重连")
            wait_until(lambda: has_text(window, "自动重连已停止"), "worker stops", timeout=90)
            screenshot(window, "stopped")
        else:
            if minimized and shell_available:
                wait_until(lambda: not user32.IsWindowVisible(hwnd), "start minimized after acknowledgement")
                assert process.poll() is None
                restore(hwnd)
            else:
                wait_until(lambda: user32.IsWindowVisible(hwnd), "visible main window")
            wait_until(lambda: has_text(window, "启动了喵"), "worker logs")
            screenshot(window, "running-minimized" if minimized else "running")
            if not minimized:
                type_into(window, "学工号 / 账号", "ci-updated-user")
                click(window, "保存并连接")
                if shell_available:
                    post(hwnd, 0x0010)
                    wait_until(lambda: not user32.IsWindowVisible(hwnd), "hide during configuration switch")
                wait_until(lambda: any(c.element_info.name.count("启动了喵") >= 2 for c in controls(window)),
                           "queued worker restarts, including while hidden", timeout=90)
                saved = tomllib.loads(config.read_text(encoding="utf-8"))
                assert saved["user_id"] == "ci-updated-user" and saved["interval_secs"] == 617
                assert saved["danger_accept_invalid_certs"] is False
                if shell_available:
                    assert not user32.IsWindowVisible(hwnd), "Worker polling must not reveal a hidden window"
                    restore(hwnd)
        all_text = "\n".join(control.element_info.name for control in controls(window))
        assert "ci-ui-password" not in all_text and "ci-test-password" not in all_text, "Password must be masked in UIA"
        if shell_available:
            post(hwnd, 0x0010)
            wait_until(lambda: not user32.IsWindowVisible(hwnd), "close hides to tray")
            assert process.poll() is None
            restore(hwnd)
            post(hwnd, 0x0112, 0xF020)  # WM_SYSCOMMAND / SC_MINIMIZE
            wait_until(lambda: not user32.IsWindowVisible(hwnd), "minimize hides to tray")
            restore(hwnd)
            click(window, "隐藏到托盘")
            wait_until(lambda: not user32.IsWindowVisible(hwnd), "hide button")
            restore(hwnd)
            print("PASS: close, minimize and hide button; tray callback restores")
        else:
            post(hwnd, 0x0010)
            wait_until(lambda: has_text(window, "托盘图标不可用"), "no-tray fallback")
            assert user32.IsWindowVisible(hwnd)
            print("SKIP: Explorer unavailable; verified visible no-tray fallback")
        click(window, "退出")
        assert process.wait(timeout=90) == 0
        print(f"PASS: clean exit (minimized={minimized}, missing={missing}, first={first_run})")
    except Exception:
        if window is not None:
            try:
                screenshot(window, "failure")
                (SCREENSHOTS / "uia-failure.txt").write_text(
                    "\n".join(f"{c.element_info.control_type}: {c.element_info.name}" for c in controls(window)),
                    encoding="utf-8",
                )
            except Exception as error:
                print(f"Could not collect UI diagnostics: {error}")
        raise
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()


def ensure_ci_font():
    fonts = pathlib.Path(os.environ.get("WINDIR", "C:/Windows")) / "Fonts"
    if any((fonts / name).is_file() for name in ["msyh.ttc", "msyh.ttf", "simhei.ttf", "simsun.ttc", "NotoSansSC.ttf"]):
        return
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise RuntimeError("Install Windows Chinese supplemental fonts before running the GUI test")
    # English Windows Server images may omit CJK fonts. Prepare a pinned OFL
    # font on the disposable runner only; the application never downloads fonts.
    # License: https://github.com/google/fonts/blob/a85815a42757630ce188fdad368c2dfc444d4773/ofl/notosanssc/OFL.txt
    url = "https://raw.githubusercontent.com/google/fonts/a85815a42757630ce188fdad368c2dfc444d4773/ofl/notosanssc/NotoSansSC%5Bwght%5D.ttf"
    data = urllib.request.urlopen(url, timeout=90).read()
    assert hashlib.sha256(data).hexdigest() == "a3041811a78c361b1de50f953c805e0244951c21c5bd412f7232ef0d899af0da"
    (fonts / "NotoSansSC.ttf").write_bytes(data)
    print("Prepared Noto Sans SC for the CI runner (OFL, SHA256 verified)")


def main():
    exe = pathlib.Path(sys.argv[1]).resolve()
    ensure_ci_font()
    with tempfile.TemporaryDirectory(prefix="yzu-smoke-") as directory:
        root = pathlib.Path(directory)
        env = dict(os.environ, LOCALAPPDATA=str(root / "local-app-data"))
        state = pathlib.Path(env["LOCALAPPDATA"]) / "Better-YZU-Campus-Network" / "ui-state.toml"
        config = root / "config.toml"
        config.write_text('user_id = "ci-test-user"\npassword = "ci-test-password"\nservice_index = 1\ninterval_secs = 617\ndanger_accept_invalid_certs = false\n', encoding="utf-8")
        result = subprocess.run([str(exe), "--help"], env=env, capture_output=True, timeout=10)
        assert result.returncode == 0 and b"--minimized" in result.stdout
        result = subprocess.run([str(exe), "--once", "--config", str(config)], env=env, capture_output=True, timeout=90)
        assert result.returncode == 0 and "启动了喵".encode() in result.stdout
        result = subprocess.run([str(exe), "--once", "--config", str(root / "missing.toml")], env=env, capture_output=True, timeout=10)
        assert result.returncode == 1
        assert not state.exists(), "CLI must not acknowledge or create GUI state"
        print("PASS: console help, --once, config errors; no GUI state created")
        # First-run --minimized + valid config must still require acknowledgement.
        exercise(exe, config, env, minimized=True, first_run=True)
        exercise(exe, config, env)
        exercise(exe, config, env, minimized=True)
        exercise(exe, root / "missing.toml", env, minimized=True, missing=True)


if __name__ == "__main__":
    main()
