use std::cell::{Cell, RefCell};
use std::error::Error;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{self, JoinHandle};

use native_windows_gui as nwg;
use winapi::shared::windef::HWND;
use winapi::um::shellapi::{Shell_NotifyIconW, NOTIFYICONDATAW, NIF_ICON, NIF_MESSAGE, NIF_TIP, NIM_ADD, NIM_DELETE, NIM_MODIFY};
use winapi::um::winuser::{KillTimer, PostMessageW, RegisterWindowMessageW, SetForegroundWindow, SetTimer, ShowWindow, SC_MINIMIZE, SW_RESTORE, WM_APP, WM_CLOSE, WM_CONTEXTMENU, WM_LBUTTONDBLCLK, WM_LBUTTONUP, WM_NULL, WM_RBUTTONUP, WM_SYSCOMMAND, WM_TIMER};

use crate::logging::LogBuffer;

const TITLE: &str = "扬州大学校园网 · v1.0.0";
const TRAY_MESSAGE: u32 = WM_APP + 20;
const TIMER_ID: usize = 1;

// NWG 的托盘 builder 不检查 Shell_NotifyIconW 的返回值。
// 在这里检查创建结果，并在 Explorer 重启后重新注册，避免隐藏后无法恢复。
struct Tray {
    data: NOTIFYICONDATAW,
    available: bool,
}

impl Tray {
    fn new(hwnd: HWND, icon: &nwg::Icon) -> Self {
        let mut data: NOTIFYICONDATAW = unsafe { std::mem::zeroed() };
        data.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
        data.hWnd = hwnd;
        data.uID = 1;
        data.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
        data.uCallbackMessage = TRAY_MESSAGE;
        data.hIcon = icon.handle as _;
        for (slot, value) in data.szTip.iter_mut().zip("校园网客户端：双击打开，右键退出".encode_utf16()) {
            *slot = value;
        }
        let mut tray = Self { data, available: false };
        tray.recreate();
        tray
    }

    fn recreate(&mut self) -> bool {
        self.available = unsafe { Shell_NotifyIconW(NIM_ADD, &mut self.data) != 0 };
        self.available
    }

    fn ensure_available(&mut self) -> bool {
        if self.available {
            self.available = unsafe { Shell_NotifyIconW(NIM_MODIFY, &mut self.data) != 0 };
        }
        self.available || self.recreate()
    }
}

impl Drop for Tray {
    fn drop(&mut self) {
        unsafe { Shell_NotifyIconW(NIM_DELETE, &mut self.data); }
    }
}

#[derive(Default)]
struct Controls {
    // 先删除托盘，再销毁父窗口及图标。
    tray: RefCell<Option<Tray>>,
    window: nwg::Window,
    icon: nwg::Icon,
    heading: nwg::Label,
    config_path: nwg::TextInput,
    hint: nwg::Label,
    log: nwg::TextBox,
    hide: nwg::Button,
    exit: nwg::Button,
    menu: nwg::Menu,
    open_item: nwg::MenuItem,
    exit_item: nwg::MenuItem,
}

struct App {
    controls: Controls,
    logs: RefCell<LogBuffer>,
    messages: Receiver<String>,
    stop: Sender<()>,
    worker: RefCell<Option<JoinHandle<Result<(), String>>>>,
    exiting: Cell<bool>,
}

impl App {
    fn restore(&self) {
        self.controls.window.set_visible(true);
        unsafe {
            let hwnd = self.controls.window.handle.hwnd().unwrap();
            ShowWindow(hwnd, SW_RESTORE);
            SetForegroundWindow(hwnd);
        }
    }

    fn hide(&self) {
        let available = self.controls.tray.borrow_mut().as_mut().is_some_and(Tray::ensure_available);
        if available {
            self.controls.window.set_visible(false);
        } else {
            self.restore();
            self.append("托盘图标不可用，窗口已保留。请使用“退出”结束程序。");
        }
    }

    fn append(&self, message: &str) {
        let mut logs = self.logs.borrow_mut();
        logs.push(message);
        self.controls.log.set_text(&logs.text());
    }

    fn exit(&self) {
        if self.exiting.replace(true) {
            return;
        }
        self.restore();
        self.controls.heading.set_text("正在退出：等待当前网络请求结束（通常不超过 15 秒）…");
        self.controls.exit.set_enabled(false);
        self.controls.hide.set_enabled(false);
        let _ = self.stop.send(());
        self.poll();
    }

    fn poll(&self) {
        for message in self.messages.try_iter() {
            self.append(&message);
        }
        let finished = self.worker.borrow().as_ref().is_some_and(JoinHandle::is_finished);
        if finished {
            let result = self.worker.borrow_mut().take().unwrap().join();
            match result {
                Ok(Ok(())) => self.controls.heading.set_text("后台任务已停止"),
                Ok(Err(error)) => {
                    self.controls.heading.set_text("启动失败：请检查配置后退出并重新打开程序");
                    self.append(&error);
                    self.restore();
                }
                Err(_) => {
                    self.controls.heading.set_text("后台任务意外停止，请退出并重新启动");
                    self.append("联网线程发生意外错误。");
                    self.restore();
                }
            }
        }
        if self.exiting.get() && self.worker.borrow().is_none() {
            nwg::stop_thread_dispatch();
        }
    }

    fn show_menu(&self) {
        unsafe { SetForegroundWindow(self.controls.window.handle.hwnd().unwrap()); }
        let (x, y) = nwg::GlobalCursor::position();
        self.controls.menu.popup(x, y);
        unsafe { PostMessageW(self.controls.window.handle.hwnd().unwrap(), WM_NULL, 0, 0); }
    }
}

pub fn run(path: PathBuf, minimized: bool) -> Result<(), Box<dyn Error>> {
    nwg::init()?;
    nwg::Font::set_global_family("Microsoft YaHei UI")?;
    let mut controls = Controls {
        icon: nwg::Icon::from_system(nwg::OemIcon::Information),
        ..Controls::default()
    };
    nwg::Window::builder()
        .title(TITLE)
        .size((700, 470))
        .center(true)
        .flags(nwg::WindowFlags::WINDOW | nwg::WindowFlags::MINIMIZE_BOX)
        .icon(Some(&controls.icon))
        .build(&mut controls.window)?;
    nwg::Label::builder()
        .text("自动登录任务运行中（实际连接结果请查看日志）")
        .position((20, 18)).size((660, 28)).parent(&controls.window)
        .build(&mut controls.heading)?;
    nwg::TextInput::builder()
        .text(&format!("配置：{}", path.display()))
        .readonly(true).position((20, 52)).size((660, 28)).parent(&controls.window)
        .build(&mut controls.config_path)?;
    nwg::Label::builder()
        .text("关闭 / 最小化会隐藏到托盘，联网任务继续运行。双击托盘图标可重新打开。")
        .position((20, 92)).size((660, 42)).parent(&controls.window)
        .build(&mut controls.hint)?;
    nwg::TextBox::builder()
        .readonly(true).limit(1_000_000)
        .flags(nwg::TextBoxFlags::VISIBLE | nwg::TextBoxFlags::VSCROLL | nwg::TextBoxFlags::AUTOVSCROLL)
        .position((20, 140)).size((660, 260)).parent(&controls.window)
        .build(&mut controls.log)?;
    nwg::Button::builder()
        .text("隐藏到托盘").position((400, 420)).size((140, 32)).parent(&controls.window)
        .build(&mut controls.hide)?;
    nwg::Button::builder()
        .text("退出").position((560, 420)).size((120, 32)).parent(&controls.window)
        .build(&mut controls.exit)?;
    nwg::Menu::builder().popup(true).parent(&controls.window).build(&mut controls.menu)?;
    nwg::MenuItem::builder().text("打开窗口").parent(&controls.menu).build(&mut controls.open_item)?;
    nwg::MenuItem::builder().text("退出").parent(&controls.menu).build(&mut controls.exit_item)?;

    let hwnd = controls.window.handle.hwnd().unwrap();
    *controls.tray.borrow_mut() = Some(Tray::new(hwnd, &controls.icon));
    let taskbar_created = unsafe {
        let name: Vec<u16> = "TaskbarCreated\0".encode_utf16().collect();
        RegisterWindowMessageW(name.as_ptr())
    };
    if taskbar_created == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let (messages_tx, messages) = mpsc::sync_channel(256);
    let (stop, receiver) = mpsc::channel();
    let app = Rc::new(App {
        controls, logs: RefCell::new(LogBuffer::default()), messages, stop,
        worker: RefCell::new(None), exiting: Cell::new(false),
    });

    let weak = Rc::downgrade(&app);
    let raw_handler = nwg::bind_raw_event_handler(&app.controls.window.handle, 0x10001, move |_, msg, w, l| {
        let app = weak.upgrade()?;
        match msg {
            WM_CLOSE => { app.hide(); return Some(0); }
            WM_SYSCOMMAND if w & 0xfff0 == SC_MINIMIZE => { app.hide(); return Some(0); }
            WM_TIMER if w == TIMER_ID => { app.poll(); return Some(0); }
            TRAY_MESSAGE => {
                match l as u32 {
                    WM_LBUTTONUP | WM_LBUTTONDBLCLK => app.restore(),
                    WM_RBUTTONUP | WM_CONTEXTMENU => app.show_menu(),
                    _ => {}
                }
                return Some(0);
            }
            _ if msg == taskbar_created => {
                let available = app.controls.tray.borrow_mut().as_mut().unwrap().recreate();
                if !available {
                    app.restore();
                    app.append("Windows 通知区域重启后未能恢复托盘图标，已显示窗口。");
                }
            }
            _ => {}
        }
        None
    })?;
    let weak = Rc::downgrade(&app);
    let event_handler = nwg::full_bind_event_handler(&app.controls.window.handle, move |event, _, handle| {
        if let Some(app) = weak.upgrade() {
            match event {
                nwg::Event::OnWindowMinimize => app.hide(),
                nwg::Event::OnButtonClick if handle == app.controls.hide.handle => app.hide(),
                nwg::Event::OnButtonClick if handle == app.controls.exit.handle => app.exit(),
                nwg::Event::OnMenuItemSelected if handle == app.controls.open_item.handle => app.restore(),
                nwg::Event::OnMenuItemSelected if handle == app.controls.exit_item.handle => app.exit(),
                _ => {}
            }
        }
    });

    // 定时从有界队列读取日志，不让工作线程访问 GUI 控件。
    let result = (|| -> Result<(), Box<dyn Error>> {
        if unsafe { SetTimer(hwnd, TIMER_ID, 200, None) } == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        *app.worker.borrow_mut() = Some(thread::Builder::new().name("campus-network".into()).spawn(move || {
            crate::logging::set_sender(messages_tx);
            crate::worker::run(&path, false, &receiver)
        })?);
        app.append("日志仅保留最近 200 行；配置修改后请退出并重新打开程序。");
        if minimized {
            app.hide();
        } else {
            app.restore();
            if !app.controls.tray.borrow().as_ref().unwrap().available {
                app.append("托盘图标创建失败，关闭/最小化时将保留窗口。");
            }
        }
        nwg::dispatch_thread_events();
        Ok(())
    })();

    unsafe { KillTimer(hwnd, TIMER_ID); }
    nwg::unbind_event_handler(&event_handler);
    let _ = nwg::unbind_raw_event_handler(&raw_handler);
    let _ = app.stop.send(());
    if let Some(worker) = app.worker.borrow_mut().take() {
        let _ = worker.join();
    }
    result
}
