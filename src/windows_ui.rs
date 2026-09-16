use std::cell::{Cell, RefCell};
use std::error::Error;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::mpsc::{self, Receiver, Sender, SyncSender};
use std::thread::{self, JoinHandle};

use native_windows_gui as nwg;
use winapi::shared::windef::HWND;
use winapi::um::shellapi::{Shell_NotifyIconW, NOTIFYICONDATAW, NIF_ICON, NIF_MESSAGE, NIF_TIP, NIM_ADD, NIM_DELETE, NIM_MODIFY};
use winapi::um::winuser::{KillTimer, PostMessageW, RegisterWindowMessageW, SetForegroundWindow, SetTimer, ShowWindow, SC_MINIMIZE, SW_RESTORE, WM_APP, WM_CLOSE, WM_CONTEXTMENU, WM_DRAWITEM, WM_ERASEBKGND, WM_LBUTTONDBLCLK, WM_LBUTTONUP, WM_NULL, WM_RBUTTONUP, WM_SYSCOMMAND, WM_TIMER};

use crate::config::{Config, ConfigError};
use crate::logging::LogBuffer;
#[path = "windows_style.rs"]
mod style;

const TITLE: &str = concat!("扬州大学校园网 · v", env!("CARGO_PKG_VERSION"));
const TRAY_MESSAGE: u32 = WM_APP + 20;
const TIMER_ID: usize = 1;

// Check tray registration and recover after Explorer restarts. Never hide an
// inaccessible window when the shell has rejected the notification icon.
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
        for (slot, value) in data.szTip.iter_mut().zip("扬大校园网 · Campus Link：点击打开，右键退出".encode_utf16()) {
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
    tray: RefCell<Option<Tray>>,
    window: nwg::Window,
    icon: nwg::Icon,
    logo_icon: nwg::Icon,
    logo: nwg::ImageFrame,
    title_font: nwg::Font,
    section_font: nwg::Font,
    body_font: nwg::Font,
    labels: Vec<nwg::Label>,
    heading: nwg::Label,
    config_path: nwg::TextInput,
    user_id: nwg::TextInput,
    password: nwg::TextInput,
    service: nwg::ComboBox<&'static str>,
    log: nwg::TextBox,
    connect: nwg::Button,
    stop: nwg::Button,
    hide: nwg::Button,
    exit: nwg::Button,
    menu: nwg::Menu,
    open_item: nwg::MenuItem,
    exit_item: nwg::MenuItem,
}

struct App {
    controls: Controls,
    path: PathBuf,
    logs: RefCell<LogBuffer>,
    messages: Receiver<String>,
    messages_tx: SyncSender<String>,
    stop: RefCell<Option<Sender<()>>>,
    worker: RefCell<Option<JoinHandle<Result<(), String>>>>,
    pending: RefCell<Option<Config>>,
    stopping: Cell<bool>,
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
        if self.exiting.get() { return; }
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

    fn status(&self, text: &str) { self.controls.heading.set_text(text); }

    fn request_stop(&self) {
        if let Some(stop) = self.stop.borrow().as_ref() { let _ = stop.send(()); }
    }

    fn start(&self, config: Config) {
        // Only poll() may replace a running worker, after it has been joined.
        if self.exiting.get() || self.worker.borrow().is_some() { return; }
        let (stop, receiver) = mpsc::channel();
        let messages = self.messages_tx.clone();
        match thread::Builder::new().name("campus-network".into()).spawn(move || {
            crate::logging::set_sender(messages);
            crate::worker::run_config(config, false, &receiver)
        }) {
            Ok(worker) => {
                *self.stop.borrow_mut() = Some(stop);
                *self.worker.borrow_mut() = Some(worker);
                self.stopping.set(false);
                self.controls.stop.set_enabled(true);
                self.status("自动重连运行中 · 连接结果请查看下方日志");
            }
            Err(_) => {
                self.status("无法启动后台任务 · 请重试“保存并连接”");
                self.append("无法创建联网线程，配置已保留。");
                self.restore();
            }
        }
    }

    fn save_and_connect(&self) {
        if self.exiting.get() || self.stopping.get() { return; }
        // Preserve advanced settings from the file; never reset them silently.
        let mut config = match Config::load(&self.path) {
            Ok(config) => config,
            Err(ConfigError::Read { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => Config::default(),
            Err(ConfigError::Parse { .. }) => {
                if !self.confirm_repair() { return; }
                Config::default()
            }
            Err(_) => {
                self.status("无法读取配置 · 请检查文件权限，未覆盖原文件");
                return;
            }
        };
        config.user_id = self.controls.user_id.text().trim().to_owned();
        // Password whitespace is meaningful. Never trim it or write it to logs.
        config.password = self.controls.password.text();
        config.service_index = self.controls.service.selection().map_or(0, |index| index + 1);
        if config.user_id.is_empty() || config.password.is_empty() {
            self.status("请填写账号和密码，再选择网络服务");
            if config.user_id.is_empty() { self.controls.user_id.set_focus(); }
            else { self.controls.password.set_focus(); }
            return;
        }
        if let Err(error) = config.save(&self.path) {
            self.status("配置未保存 · 当前后台任务不受影响");
            nwg::modal_error_message(&self.controls.window, "无法保存配置", &error);
            return;
        }
        self.append("配置已保存。账号和密码不会显示在日志中。");
        if self.worker.borrow().is_some() {
            *self.pending.borrow_mut() = Some(config);
            self.stopping.set(true);
            self.controls.connect.set_enabled(false);
            self.status("正在切换配置 · 等待当前请求结束后重新连接…");
            self.request_stop();
        } else {
            self.start(config);
        }
    }

    fn confirm_repair(&self) -> bool {
        use winapi::um::winuser::{MessageBoxW, IDYES, MB_DEFBUTTON2, MB_ICONWARNING, MB_YESNO};
        let text: Vec<u16> = "原配置格式错误。是否用当前表单重建？\n高级设置将恢复默认值，原文件中的注释和其他字段将被替换。\n如需保留原文件，请先取消并备份。\0".encode_utf16().collect();
        let title: Vec<u16> = "重建配置\0".encode_utf16().collect();
        unsafe { MessageBoxW(self.controls.window.handle.hwnd().unwrap(), text.as_ptr(), title.as_ptr(), MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) == IDYES }
    }

    fn stop(&self) {
        if self.exiting.get() { return; }
        self.pending.borrow_mut().take();
        if self.worker.borrow().is_some() {
            self.stopping.set(true);
            self.controls.connect.set_enabled(false);
            self.controls.stop.set_enabled(false);
            self.status("正在停止自动重连 · 等待当前网络请求结束…");
            self.request_stop();
        }
    }

    fn exit(&self) {
        if self.exiting.replace(true) { return; }
        self.pending.borrow_mut().take();
        self.restore();
        self.status("正在退出 · 等待当前探测 / 认证请求结束…");
        self.controls.exit.set_enabled(false);
        self.controls.hide.set_enabled(false);
        self.controls.connect.set_enabled(false);
        self.controls.stop.set_enabled(false);
        self.request_stop();
        self.poll();
    }

    fn poll(&self) {
        for message in self.messages.try_iter() { self.append(&message); }
        let finished = self.worker.borrow().as_ref().is_some_and(JoinHandle::is_finished);
        if finished {
            let result = self.worker.borrow_mut().take().unwrap().join();
            self.stop.borrow_mut().take();
            // Drain the final old-worker messages before a new worker is started.
            for message in self.messages.try_iter() { self.append(&message); }
            self.stopping.set(false);
            self.controls.stop.set_enabled(false);
            if !self.exiting.get() {
                self.controls.connect.set_enabled(true);
                match result {
                    Ok(Ok(())) => self.status("自动重连已停止 · 可保存并重新连接"),
                    Ok(Err(error)) => {
                        self.status("后台任务已停止 · 检查配置后重试");
                        self.append(&error);
                        self.restore();
                    }
                    Err(_) => {
                        self.status("后台任务意外停止 · 可重新连接");
                        self.append("联网线程发生意外错误。");
                        self.restore();
                    }
                }
                let next = self.pending.borrow_mut().take();
                if let Some(config) = next { self.start(config); }
            }
        }
        if self.exiting.get() && self.worker.borrow().is_none() { nwg::stop_thread_dispatch(); }
    }

    fn show_menu(&self) {
        unsafe { SetForegroundWindow(self.controls.window.handle.hwnd().unwrap()); }
        let (x, y) = nwg::GlobalCursor::position();
        self.controls.menu.popup(x, y);
        unsafe { PostMessageW(self.controls.window.handle.hwnd().unwrap(), WM_NULL, 0, 0); }
    }
}

fn label(controls: &mut Controls, text: &str, position: (i32, i32), size: (i32, i32), card: bool, title: bool) -> Result<(), nwg::NwgError> {
    let mut label = nwg::Label::default();
    nwg::Label::builder().text(text).position(position).size(size)
        .font(Some(if title { &controls.title_font } else { &controls.body_font }))
        .background_color(Some(if card { style::CARD } else { style::BACKGROUND }))
        .parent(&controls.window).build(&mut label)?;
    controls.labels.push(label);
    Ok(())
}

pub fn run(path: PathBuf, minimized: bool) -> Result<(), Box<dyn Error>> {
    nwg::init()?;
    nwg::Font::set_global_family("Microsoft YaHei UI")?;
    let initial = Config::load(&path);
    let valid = initial.as_ref().is_ok_and(|config| config.validate().is_ok());
    let initial_message = match &initial {
        Ok(_) if valid => "准备连接 · 自动重连即将启动",
        Ok(_) => "请检查账号、密码和服务 · 保存后即可连接",
        Err(ConfigError::Read { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => "欢迎使用 · 填写以下三项，即可开始连接",
        Err(_) => "配置无法读取 · 请检查文件或在表单中重新设置",
    };
    let mut controls = Controls::default();
    let resources = nwg::EmbedResource::load(None)?;
    // winres::set_icon uses resource ID 1. LoadImage chooses the matching ICO
    // frame instead of WIC's frame(0), keeping window and header icons crisp.
    nwg::Icon::builder().source_embed(Some(&resources)).source_embed_id(1).size(Some((32, 32))).build(&mut controls.icon)?;
    nwg::Icon::builder().source_embed(Some(&resources)).source_embed_id(1).size(Some((64, 64))).build(&mut controls.logo_icon)?;
    nwg::Font::builder().family("Microsoft YaHei UI").size(27).weight(700).build(&mut controls.title_font)?;
    nwg::Font::builder().family("Microsoft YaHei UI").size(15).weight(600).build(&mut controls.section_font)?;
    nwg::Font::builder().family("Microsoft YaHei UI").size(14).build(&mut controls.body_font)?;
    nwg::Window::builder().title(TITLE).size((760, 680)).center(true)
        .flags(nwg::WindowFlags::WINDOW | nwg::WindowFlags::MINIMIZE_BOX)
        .icon(Some(&controls.icon)).build(&mut controls.window)?;
    nwg::ImageFrame::builder().icon(Some(&controls.logo_icon)).position((28, 26)).size((64, 64))
        .background_color(Some(style::BACKGROUND)).parent(&controls.window).build(&mut controls.logo)?;
    label(&mut controls, "扬大校园网", (112, 24), (500, 40), false, true)?;
    label(&mut controls, "CAMPUS LINK  /  让连接更简单", (114, 69), (550, 24), false, false)?;
    label(&mut controls, "账户与网络", (44, 132), (350, 24), true, false)?;
    label(&mut controls, "学工号 / 账号", (44, 170), (300, 22), true, false)?;
    label(&mut controls, "校园网密码", (396, 170), (300, 22), true, false)?;
    nwg::TextInput::builder().position((44, 198)).size((320, 34)).font(Some(&controls.body_font))
        .parent(&controls.window).build(&mut controls.user_id)?;
    nwg::TextInput::builder().position((396, 198)).size((320, 34)).font(Some(&controls.body_font))
        .password(Some('●')).parent(&controls.window).build(&mut controls.password)?;
    label(&mut controls, "网络服务", (44, 248), (260, 22), true, false)?;
    nwg::ComboBox::builder().collection(crate::login::SERVICE_LIST.to_vec()).selected_index(Some(0))
        .position((44, 276)).size((320, 130)).font(Some(&controls.body_font))
        .parent(&controls.window).build(&mut controls.service)?;
    label(&mut controls, "默认每 10 分钟检查一次\n密码仅以明文保存在本机配置文件", (396, 267), (320, 52), true, false)?;
    nwg::Label::builder().text(initial_message).position((32, 364)).size((696, 26))
        .font(Some(&controls.section_font)).background_color(Some(style::BACKGROUND))
        .parent(&controls.window).build(&mut controls.heading)?;
    label(&mut controls, "连接记录", (44, 413), (240, 24), true, false)?;
    label(&mut controls, "最近 200 行 · 敏感信息已遮蔽", (434, 413), (280, 24), true, false)?;
    nwg::TextBox::builder().readonly(true).limit(1_000_000).font(Some(&controls.body_font))
        .flags(nwg::TextBoxFlags::VISIBLE | nwg::TextBoxFlags::VSCROLL | nwg::TextBoxFlags::AUTOVSCROLL)
        .position((44, 445)).size((672, 108)).parent(&controls.window).build(&mut controls.log)?;
    nwg::TextInput::builder().text(&format!("配置：{}", path.display())).readonly(true)
        .position((28, 582)).size((704, 26)).font(Some(&controls.body_font))
        .parent(&controls.window).build(&mut controls.config_path)?;
    for (text, x, width, button) in [
        ("保存并连接", 28, 184, &mut controls.connect),
        ("停止重连", 228, 144, &mut controls.stop),
        ("隐藏到托盘", 420, 164, &mut controls.hide),
        ("退出", 600, 132, &mut controls.exit),
    ] {
        nwg::Button::builder().text(text).position((x, 624)).size((width, 38))
            .font(Some(&controls.body_font)).parent(&controls.window).build(button)?;
        style::owner_draw(button);
    }
    controls.stop.set_enabled(false);
    if let Ok(config) = &initial {
        controls.user_id.set_text(&config.user_id);
        controls.password.set_text(&config.password);
        controls.service.set_selection(config.service_index.checked_sub(1).filter(|i| *i < crate::config::SERVICE_COUNT));
    }
    nwg::Menu::builder().popup(true).parent(&controls.window).build(&mut controls.menu)?;
    nwg::MenuItem::builder().text("打开窗口").parent(&controls.menu).build(&mut controls.open_item)?;
    nwg::MenuItem::builder().text("退出").parent(&controls.menu).build(&mut controls.exit_item)?;
    let hwnd = controls.window.handle.hwnd().unwrap();
    *controls.tray.borrow_mut() = Some(Tray::new(hwnd, &controls.icon));
    let taskbar_created = unsafe {
        let name: Vec<u16> = "TaskbarCreated\0".encode_utf16().collect();
        RegisterWindowMessageW(name.as_ptr())
    };
    if taskbar_created == 0 { return Err(std::io::Error::last_os_error().into()); }
    let (messages_tx, messages) = mpsc::sync_channel(256);
    let app = Rc::new(App {
        controls, path, logs: RefCell::new(LogBuffer::default()), messages, messages_tx,
        stop: RefCell::new(None), worker: RefCell::new(None), pending: RefCell::new(None),
        stopping: Cell::new(false), exiting: Cell::new(false),
    });
    let weak = Rc::downgrade(&app);
    let raw_handler = nwg::bind_raw_event_handler(&app.controls.window.handle, 0x10001, move |hwnd, msg, w, l| {
        let app = weak.upgrade()?;
        match msg {
            WM_ERASEBKGND => return Some(style::background(hwnd, w as _)),
            WM_DRAWITEM => return style::button(l, app.controls.connect.handle.hwnd().unwrap()),
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
                if !app.controls.tray.borrow_mut().as_mut().unwrap().recreate() {
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
                nwg::Event::OnButtonClick if handle == app.controls.connect.handle => app.save_and_connect(),
                nwg::Event::OnButtonClick if handle == app.controls.stop.handle => app.stop(),
                nwg::Event::OnButtonClick if handle == app.controls.hide.handle => app.hide(),
                nwg::Event::OnButtonClick if handle == app.controls.exit.handle => app.exit(),
                nwg::Event::OnMenuItemSelected if handle == app.controls.open_item.handle => app.restore(),
                nwg::Event::OnMenuItemSelected if handle == app.controls.exit_item.handle => app.exit(),
                _ => {}
            }
        }
    });
    let result = (|| -> Result<(), Box<dyn Error>> {
        if unsafe { SetTimer(hwnd, TIMER_ID, 200, None) } == 0 { return Err(std::io::Error::last_os_error().into()); }
        app.append("关闭 / 最小化会隐藏到托盘。停止重连不会注销当前网络。修改后请点击“保存并连接”。");
        if valid {
            app.start(initial.unwrap());
        } else {
            app.append("请填写账号和密码并选择服务；首次保存使用默认高级设置。");
        }
        // A missing/bad configuration must never disappear on first run.
        if minimized && valid && app.worker.borrow().is_some() { app.hide(); }
        else {
            app.restore();
            if !valid { app.controls.user_id.set_focus(); }
        }
        nwg::dispatch_thread_events();
        Ok(())
    })();
    unsafe { KillTimer(hwnd, TIMER_ID); }
    nwg::unbind_event_handler(&event_handler);
    let _ = nwg::unbind_raw_event_handler(&raw_handler);
    app.pending.borrow_mut().take();
    app.request_stop();
    if let Some(worker) = app.worker.borrow_mut().take() { let _ = worker.join(); }
    result
}
