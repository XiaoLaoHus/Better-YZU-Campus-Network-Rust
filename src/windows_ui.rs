use std::error::Error;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, Sender, SyncSender};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use eframe::egui::{self, RichText};
use raw_window_handle::{HasWindowHandle, RawWindowHandle};

use crate::config::{Config, ConfigError};
use crate::logging::LogBuffer;
use crate::ui_state::{UiState, NOTICE};
#[path = "windows_style.rs"]
mod style;
#[path = "windows_tray.rs"]
mod tray;

const TITLE: &str = concat!("扬州大学校园网 · v", env!("CARGO_PKG_VERSION"));

enum Dialog { Error(String), Repair }

struct App {
    tray: tray::Tray,
    logo: egui::TextureHandle,
    path: PathBuf,
    user_id: String,
    password: String,
    service_index: usize,
    status: String,
    logs: LogBuffer,
    log_text: String,
    messages: Receiver<String>,
    messages_tx: SyncSender<String>,
    stop: Option<Sender<()>>,
    worker: Option<JoinHandle<Result<(), String>>>,
    pending: Option<Config>,
    initial: Option<Config>,
    stopping: bool,
    exiting: bool,
    startup_done: bool,
    minimized: bool,
    ui_state: UiState,
    notice: bool,
    dialog: Option<Dialog>,
}

impl App {
    fn append(&mut self, message: &str) {
        self.logs.push(message);
        self.log_text = self.logs.text();
    }

    fn request_stop(&self) {
        if let Some(stop) = &self.stop { let _ = stop.send(()); }
    }

    fn start(&mut self, config: Config) {
        if self.exiting || self.worker.is_some() { return; }
        let (stop, receiver) = mpsc::channel();
        let messages = self.messages_tx.clone();
        match thread::Builder::new().name("campus-network".into()).spawn(move || {
            crate::logging::set_sender(messages);
            crate::worker::run_config(config, false, &receiver)
        }) {
            Ok(worker) => {
                self.stop = Some(stop);
                self.worker = Some(worker);
                self.stopping = false;
                self.status = "自动重连运行中 · 连接结果请查看下方日志".into();
            }
            Err(_) => {
                self.status = "无法启动后台任务 · 请重试“保存并连接”".into();
                self.append("无法创建联网线程，配置已保留。");
                self.tray.restore();
            }
        }
    }

    fn save_and_connect(&mut self, repair: bool, ctx: &egui::Context) {
        if self.exiting || self.stopping { return; }
        // Reload at confirmation time, preserving advanced settings even if the file changed.
        let mut config = match Config::load(&self.path) {
            Ok(config) => config,
            Err(ConfigError::Read { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => Config::default(),
            Err(ConfigError::Parse { .. }) if repair => Config::default(),
            Err(ConfigError::Parse { .. }) => { self.dialog = Some(Dialog::Repair); return; }
            Err(_) => { self.status = "无法读取配置 · 请检查文件权限，未覆盖原文件".into(); return; }
        };
        config.user_id = self.user_id.trim().to_owned();
        // Password whitespace is meaningful. Never trim it or write it to logs.
        config.password = self.password.clone();
        config.service_index = self.service_index;
        if config.user_id.is_empty() || config.password.is_empty() {
            self.status = "请填写账号和密码，再选择网络服务".into();
            let id = if config.user_id.is_empty() { "user-id" } else { "password" };
            ctx.memory_mut(|memory| memory.request_focus(egui::Id::new(id)));
            return;
        }
        if let Err(error) = config.save(&self.path) {
            self.status = "配置未保存 · 当前后台任务不受影响".into();
            self.dialog = Some(Dialog::Error(error));
            return;
        }
        self.append("配置已保存。账号和密码不会显示在日志中。");
        if self.worker.is_some() {
            self.pending = Some(config);
            self.stopping = true;
            self.status = "正在切换配置 · 等待当前请求结束后重新连接…".into();
            self.request_stop();
        } else {
            self.start(config);
        }
    }

    fn stop(&mut self) {
        if self.exiting { return; }
        self.pending = None;
        if self.worker.is_some() {
            self.stopping = true;
            self.status = "正在停止自动重连 · 等待当前网络请求结束…".into();
            self.request_stop();
        }
    }

    fn exit(&mut self) {
        if self.exiting { return; }
        self.exiting = true;
        self.pending = None;
        self.dialog = None;
        self.tray.set_allow_hide(false);
        self.tray.restore();
        self.status = "正在退出 · 等待当前探测 / 认证请求结束…".into();
        self.request_stop();
    }

    fn drain_logs(&mut self) {
        while let Ok(message) = self.messages.try_recv() { self.append(&message); }
    }

    fn poll(&mut self, ctx: &egui::Context) {
        while let Ok(event) = self.tray.events.try_recv() {
            match event {
                tray::Event::Exit => self.exit(),
                tray::Event::Unavailable => self.append("托盘图标不可用，窗口已保留。请使用“退出”结束程序。"),
            }
        }
        self.drain_logs();
        if self.worker.as_ref().is_some_and(JoinHandle::is_finished) {
            let result = self.worker.take().unwrap().join();
            self.stop = None;
            self.drain_logs();
            self.stopping = false;
            if !self.exiting {
                match result {
                    Ok(Ok(())) => self.status = "自动重连已停止 · 可保存并重新连接".into(),
                    Ok(Err(error)) => {
                        self.status = "后台任务已停止 · 检查配置后重试".into();
                        self.append(&error);
                        self.tray.restore();
                    }
                    Err(_) => {
                        self.status = "后台任务意外停止 · 可重新连接".into();
                        self.append("联网线程发生意外错误。");
                        self.tray.restore();
                    }
                }
                if let Some(config) = self.pending.take() { self.start(config); }
            }
        }
        if self.exiting && self.worker.is_none() {
            self.tray.allow_close();
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
    }

    fn startup(&mut self, ctx: &egui::Context) {
        if self.startup_done || self.notice || self.dialog.is_some() || self.exiting { return; }
        // eframe shows the window after its first rendered frame. Hiding earlier
        // would be undone by that initial show, breaking --minimized.
        if !self.tray.is_visible() { return; }
        self.startup_done = true;
        if let Some(config) = self.initial.take() {
            self.start(config);
        } else {
            self.append("请填写账号和密码并选择服务；首次保存使用默认高级设置。");
            ctx.memory_mut(|memory| memory.request_focus(egui::Id::new("user-id")));
        }
        self.tray.set_allow_hide(true);
        if self.minimized && self.worker.is_some() { self.tray.hide(); }
    }

    fn content(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        ui.horizontal(|ui| {
            ui.add(egui::Image::new(&self.logo).fit_to_exact_size(egui::vec2(64.0, 64.0)));
            ui.add_space(8.0);
            ui.vertical(|ui| {
                ui.heading(RichText::new("扬大校园网").strong());
                ui.label(RichText::new("CAMPUS LINK  /  让连接更简单").color(style::MUTED));
            });
        });
        ui.add_space(12.0);
        style::card().show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(RichText::new("账户与网络").strong().size(17.0));
            ui.add_space(4.0);
            ui.columns(2, |columns| {
                let label = columns[0].label("学工号 / 账号");
                columns[0].add(style::input(&mut self.user_id, "user-id", false)).labelled_by(label.id);
                let label = columns[1].label("校园网密码");
                columns[1].add(style::input(&mut self.password, "password", true)).labelled_by(label.id);
            });
            ui.add_space(8.0);
            ui.columns(2, |columns| {
                let label = columns[0].label("网络服务");
                let selected = self.service_index.checked_sub(1).and_then(|i| crate::login::SERVICE_LIST.get(i))
                    .copied().unwrap_or("请选择网络服务");
                let enabled = columns[0].is_enabled();
                let selector = egui::ComboBox::from_id_salt("service").width(columns[0].available_width()).selected_text(selected)
                    .show_ui(&mut columns[0], |ui| {
                        for (i, name) in crate::login::SERVICE_LIST.iter().enumerate() {
                            ui.selectable_value(&mut self.service_index, i + 1, *name);
                        }
                    }).response.labelled_by(label.id);
                // from_id_salt 会让 egui 把 accesskit 名字设成空串，反而盖住 labelled_by 关系，
                // 读屏和 UI 自动化据此才拿得到「网络服务」这个名字。
                selector.widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::ComboBox, enabled, "网络服务"));
                columns[1].add_space(20.0);
                columns[1].label(RichText::new("默认每 10 分钟检查一次\n密码仅以明文保存在本机配置文件").small().color(style::MUTED));
            });
        });
        ui.add_space(2.0);
        ui.label(RichText::new(&self.status).color(style::ACCENT).strong());
        ui.add_space(2.0);
        style::card().show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(RichText::new("连接记录").strong().size(17.0));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.small_button("复制日志").clicked() { ctx.copy_text(self.log_text.clone()); }
                    ui.label(RichText::new("最近 200 行 · 敏感信息已遮蔽").small().color(style::MUTED));
                });
            });
            egui::ScrollArea::vertical().id_salt("log-scroll").max_height(136.0).min_scrolled_height(136.0)
                .stick_to_bottom(true).show(ui, |ui| {
                    ui.add(egui::Label::new(&self.log_text).selectable(true).wrap());
                });
        });
        egui::ScrollArea::horizontal().id_salt("config-path").show(ui, |ui| {
            ui.add(egui::Label::new(RichText::new(format!("配置：{}", self.path.display())).small().color(style::MUTED)).selectable(true));
        });
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            if ui.add_enabled(!self.exiting && !self.stopping, style::primary("保存并连接")).clicked() {
                self.save_and_connect(false, ctx);
            }
            if ui.add_enabled(!self.exiting && self.worker.is_some() && (!self.stopping || self.pending.is_some()), egui::Button::new("停止重连")).clicked() {
                self.stop();
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.add_enabled(!self.exiting, egui::Button::new("退出")).clicked() { self.exit(); }
                if ui.add_enabled(!self.exiting, egui::Button::new("隐藏到托盘")).clicked() { self.tray.hide(); }
            });
        });
    }

    fn dialogs(&mut self, ctx: &egui::Context) {
        if self.notice && !self.exiting {
            let mut accept = false;
            let mut exit = false;
            egui::Modal::new(egui::Id::new("beta-notice")).frame(style::card()).show(ctx, |ui| {
                ui.set_width(440.0);
                ui.label(RichText::new("测试版使用提示").strong().size(22.0));
                ui.add_space(8.0);
                ui.label(NOTICE);
                ui.add_space(4.0);
                ui.label(RichText::new("作者 QQ：2576381123").strong().color(style::ACCENT));
                if ui.button("复制作者 QQ").clicked() { ctx.copy_text("2576381123".into()); }
                ui.label(RichText::new("确认后不再提示。请勿向他人发送账号、密码或配置文件。").small().color(style::MUTED));
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    accept = ui.add(style::primary("我已了解")).clicked();
                    exit = ui.button("退出程序").clicked();
                });
            });
            if accept {
                self.notice = false;
                if let Err(error) = self.ui_state.acknowledge() {
                    self.dialog = Some(Dialog::Error(format!("无法保存提示确认状态：{error}。\n本次可以继续使用，下次启动可能仍会显示测试版提示。")));
                }
            }
            if exit { self.exit(); }
            return;
        }
        let mut dismiss = false;
        let mut repair = false;
        if let Some(dialog) = &self.dialog {
            egui::Modal::new(egui::Id::new("message-dialog")).frame(style::card()).show(ctx, |ui| {
                ui.set_width(440.0);
                match dialog {
                    Dialog::Error(message) => {
                        ui.label(RichText::new("操作提示").strong().size(22.0));
                        ui.label(message);
                        dismiss = ui.add(style::primary("确定")).clicked();
                    }
                    Dialog::Repair => {
                        ui.label(RichText::new("重建配置？").strong().size(22.0));
                        ui.label("原配置格式错误。是否用当前表单重建？\n高级设置将恢复默认值，原文件中的注释和其他字段将被替换。\n如需保留原文件，请先取消并备份。");
                        ui.horizontal(|ui| {
                            dismiss = ui.button("取消").clicked();
                            repair = ui.button("确认重建").clicked();
                        });
                    }
                }
            });
        }
        if dismiss || repair { self.dialog = None; }
        if repair { self.save_and_connect(true, ctx); }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll(ctx);
        self.startup(ctx);
        self.tray.set_allow_hide(self.startup_done && !self.notice && self.dialog.is_none() && !self.exiting);
        egui::CentralPanel::default().frame(egui::Frame::new().fill(style::BACKGROUND).inner_margin(24)).show(ctx, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                ui.add_enabled_ui(!self.notice && self.dialog.is_none() && !self.exiting, |ui| self.content(ui, ctx));
            });
        });
        self.dialogs(ctx);
        ctx.request_repaint_after(Duration::from_millis(200));
    }
}

impl Drop for App {
    fn drop(&mut self) {
        self.pending = None;
        self.request_stop();
        if let Some(worker) = self.worker.take() { let _ = worker.join(); }
    }
}

pub fn startup_error(message: &str) {
    use winapi::um::winuser::{MessageBoxW, MB_ICONERROR, MB_OK};
    let title: Vec<u16> = "校园网客户端启动失败\0".encode_utf16().collect();
    let text: Vec<u16> = message.encode_utf16().chain(Some(0)).collect();
    unsafe { MessageBoxW(std::ptr::null_mut(), text.as_ptr(), title.as_ptr(), MB_OK | MB_ICONERROR); }
}

pub fn run(path: PathBuf, minimized: bool) -> Result<(), Box<dyn Error>> {
    let image = image::load_from_memory(include_bytes!("../assets/campus-link.png"))?.into_rgba8();
    let (width, height) = image.dimensions();
    let icon = egui::IconData { rgba: image.as_raw().clone(), width, height };
    let logo = egui::ColorImage::from_rgba_unmultiplied([width as usize, height as usize], image.as_raw());
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_title(TITLE).with_inner_size([780.0, 710.0])
            .with_min_inner_size([620.0, 420.0]).with_icon(icon),
        renderer: eframe::Renderer::Wgpu,
        centered: true,
        ..Default::default()
    };
    eframe::run_native(TITLE, options, Box::new(move |cc| {
        style::setup(&cc.egui_ctx)?;
        let handle = cc.window_handle().map_err(|error| format!("无法获取窗口句柄：{error}"))?;
        let RawWindowHandle::Win32(window) = handle.as_raw() else {
            return Err("无法获取 Windows 窗口句柄".into());
        };
        let tray = tray::Tray::new(window.hwnd.get() as _, cc.egui_ctx.clone())?;
        let initial = Config::load(&path);
        let valid = initial.as_ref().is_ok_and(|config| config.validate().is_ok());
        let status = match &initial {
            Ok(_) if valid => "准备连接 · 自动重连即将启动",
            Ok(_) => "请检查账号、密码和服务 · 保存后即可连接",
            Err(ConfigError::Read { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => "欢迎使用 · 填写以下三项，即可开始连接",
            Err(_) => "配置无法读取 · 请检查文件或在表单中重新设置",
        }.into();
        let (user_id, password, service_index) = initial.as_ref()
            .map(|config| (config.user_id.clone(), config.password.clone(), config.service_index))
            .unwrap_or_else(|_| (String::new(), String::new(), 1));
        let (messages_tx, messages) = mpsc::sync_channel(256);
        let ui_state = UiState::load();
        let notice = !ui_state.acknowledged();
        let mut app = App {
            tray, logo: cc.egui_ctx.load_texture("campus-link", logo, egui::TextureOptions::LINEAR),
            path, user_id, password, service_index, status, logs: LogBuffer::default(), log_text: String::new(),
            messages, messages_tx, stop: None, worker: None, pending: None,
            initial: initial.ok().filter(|_| valid), stopping: false, exiting: false, startup_done: false,
            minimized, ui_state, notice, dialog: None,
        };
        app.append("关闭 / 最小化会隐藏到托盘。停止重连不会注销当前网络。修改后请点击“保存并连接”。");
        Ok(Box::new(app))
    }))?;
    Ok(())
}
