//! Shell integration only. All client-area widgets and dialogs are drawn by egui.
use std::cell::Cell;
use std::io;
use std::sync::mpsc::{self, Receiver, Sender};

use eframe::egui;
use winapi::shared::{basetsd::{DWORD_PTR, UINT_PTR}, minwindef::{LPARAM, LRESULT, UINT, WPARAM}, windef::{HICON, HWND, POINT}};
use winapi::um::{commctrl::{DefSubclassProc, RemoveWindowSubclass, SetWindowSubclass}, libloaderapi::GetModuleHandleW, shellapi::*, winuser::*};

pub const TRAY_MESSAGE: UINT = WM_APP + 20;
const SUBCLASS_ID: UINT_PTR = 0x595a55;
const TIMER_ID: UINT_PTR = 0x595a56;

pub enum Event { Exit, Unavailable }

struct State {
    hwnd: HWND,
    data: Cell<NOTIFYICONDATAW>,
    available: Cell<bool>,
    allow_hide: Cell<bool>,
    allow_close: Cell<bool>,
    taskbar_created: UINT,
    events: Sender<Event>,
    ctx: egui::Context,
}

impl State {
    fn register(&self, operation: u32) -> bool {
        let mut data = self.data.get();
        let success = unsafe { Shell_NotifyIconW(operation, &mut data) != 0 };
        self.available.set(success);
        success
    }

    fn restore(&self) {
        unsafe { ShowWindow(self.hwnd, SW_RESTORE); SetForegroundWindow(self.hwnd); }
        self.ctx.request_repaint();
    }

    fn hide(&self) {
        if !self.allow_hide.get() { self.restore(); return; }
        let available = (self.available.get() && self.register(NIM_MODIFY)) || self.register(NIM_ADD);
        if available {
            unsafe { ShowWindow(self.hwnd, SW_HIDE); }
        } else {
            self.restore();
            let _ = self.events.send(Event::Unavailable);
        }
    }

    fn menu(&self) {
        unsafe {
            let menu = CreatePopupMenu();
            if menu.is_null() { self.restore(); return; }
            let open: Vec<u16> = "打开窗口\0".encode_utf16().collect();
            let exit: Vec<u16> = "退出\0".encode_utf16().collect();
            AppendMenuW(menu, MF_STRING, 1, open.as_ptr());
            AppendMenuW(menu, MF_STRING, 2, exit.as_ptr());
            let mut position: POINT = std::mem::zeroed();
            GetCursorPos(&mut position);
            SetForegroundWindow(self.hwnd);
            let command = TrackPopupMenu(menu, TPM_RETURNCMD | TPM_NONOTIFY | TPM_RIGHTBUTTON,
                position.x, position.y, 0, self.hwnd, std::ptr::null());
            DestroyMenu(menu);
            PostMessageW(self.hwnd, WM_NULL, 0, 0);
            match command {
                1 => self.restore(),
                2 => { let _ = self.events.send(Event::Exit); self.restore(); }
                _ => {}
            }
        }
    }
}

unsafe extern "system" fn window_proc(hwnd: HWND, message: UINT, w: WPARAM, l: LPARAM, id: UINT_PTR, data: DWORD_PTR) -> LRESULT {
    let state = &*(data as *const State);
    match message {
        WM_CLOSE if !state.allow_close.get() => { state.hide(); return 0; }
        WM_SYSCOMMAND if w & 0xfff0 == SC_MINIMIZE => { state.hide(); return 0; }
        TRAY_MESSAGE => {
            match l as UINT {
                WM_LBUTTONUP | WM_LBUTTONDBLCLK => state.restore(),
                WM_RBUTTONUP | WM_CONTEXTMENU => state.menu(),
                _ => {}
            }
            return 0;
        }
        WM_TIMER if w == TIMER_ID => {
            // Winit's request_redraw uses RedrawWindow, which does not generate
            // WM_PAINT for hidden windows. Keep polling worker completion and
            // queued restarts while in the tray, without showing the window.
            if IsWindowVisible(hwnd) == 0 { PostMessageW(hwnd, WM_PAINT, 0, 0); }
            return 0;
        }
        WM_NCDESTROY => { RemoveWindowSubclass(hwnd, Some(window_proc), id); }
        _ if message == state.taskbar_created => {
            if !state.register(NIM_ADD) {
                state.restore();
                let _ = state.events.send(Event::Unavailable);
            }
        }
        _ => {}
    }
    DefSubclassProc(hwnd, message, w, l)
}

pub struct Tray {
    state: Box<State>,
    pub events: Receiver<Event>,
    icon: HICON,
}

impl Tray {
    pub fn new(hwnd: HWND, ctx: egui::Context) -> io::Result<Self> {
        unsafe {
            let name: Vec<u16> = "TaskbarCreated\0".encode_utf16().collect();
            let taskbar_created = RegisterWindowMessageW(name.as_ptr());
            if taskbar_created == 0 { return Err(io::Error::last_os_error()); }
            let icon = LoadImageW(GetModuleHandleW(std::ptr::null()), 1usize as _, IMAGE_ICON,
                GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), LR_DEFAULTCOLOR) as HICON;
            if icon.is_null() { return Err(io::Error::last_os_error()); }
            let mut data: NOTIFYICONDATAW = std::mem::zeroed();
            data.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
            data.hWnd = hwnd;
            data.uID = 1;
            data.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
            data.uCallbackMessage = TRAY_MESSAGE;
            data.hIcon = icon;
            for (slot, value) in data.szTip.iter_mut().zip("扬大校园网 · Campus Link：点击打开，右键退出".encode_utf16()) { *slot = value; }
            let (events, receiver) = mpsc::channel();
            let state = Box::new(State {
                hwnd, data: Cell::new(data), available: Cell::new(false), allow_hide: Cell::new(false),
                allow_close: Cell::new(false), taskbar_created, events, ctx,
            });
            if SetWindowSubclass(hwnd, Some(window_proc), SUBCLASS_ID, &*state as *const State as DWORD_PTR) == 0 {
                let error = io::Error::last_os_error();
                DestroyIcon(icon);
                return Err(error);
            }
            if SetTimer(hwnd, TIMER_ID, 200, None) == 0 {
                let error = io::Error::last_os_error();
                RemoveWindowSubclass(hwnd, Some(window_proc), SUBCLASS_ID);
                DestroyIcon(icon);
                return Err(error);
            }
            state.register(NIM_ADD);
            Ok(Self { state, events: receiver, icon })
        }
    }

    pub fn is_visible(&self) -> bool { unsafe { IsWindowVisible(self.state.hwnd) != 0 } }
    pub fn set_allow_hide(&self, allowed: bool) { self.state.allow_hide.set(allowed); }
    pub fn allow_close(&self) { self.state.allow_close.set(true); }
    pub fn restore(&self) { self.state.restore(); }
    pub fn hide(&self) { self.state.hide(); }
}

impl Drop for Tray {
    fn drop(&mut self) {
        unsafe {
            KillTimer(self.state.hwnd, TIMER_ID);
            RemoveWindowSubclass(self.state.hwnd, Some(window_proc), SUBCLASS_ID);
            let mut data = self.state.data.get();
            Shell_NotifyIconW(NIM_DELETE, &mut data);
            DestroyIcon(self.icon);
        }
    }
}
