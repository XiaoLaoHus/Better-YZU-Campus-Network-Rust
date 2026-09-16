#![cfg_attr(windows, windows_subsystem = "windows")]

mod config;
mod logging;
mod login;
mod worker;
#[cfg(windows)]
mod windows_ui;

use std::env;
use std::path::PathBuf;
use std::sync::mpsc;

use config::CONFIG_FILE;

const USAGE: &str = "\
用法: better-yzu-campus-network [选项]

选项:
  -c, --config <路径>  指定配置文件路径
      --once           只尝试登录一次后退出（命令行模式）
      --console        使用命令行模式，不创建托盘图标
      --minimized      启动时隐藏到托盘（仅 Windows）
  -h, --help           显示本帮助

Windows 默认打开图形窗口，配置默认位于程序所在目录。
命令行模式默认读取当前目录的 config.toml。
";

#[derive(Debug, Default)]
struct Args {
    once: bool,
    console: bool,
    minimized: bool,
    help: bool,
    config_path: Option<PathBuf>,
}

fn parse_args(iter: impl IntoIterator<Item = std::ffi::OsString>) -> Result<Args, String> {
    let mut args = Args::default();
    let mut iter = iter.into_iter();
    while let Some(arg) = iter.next() {
        match arg.to_str() {
            Some("--once") => args.once = true,
            Some("--console") => args.console = true,
            Some("--minimized") => args.minimized = true,
            Some("-c" | "--config") => {
                args.config_path = Some(iter.next().ok_or("--config 需要一个参数")?.into());
            }
            Some("-h" | "--help") => args.help = true,
            _ => return Err(format!("未知参数: {}", arg.to_string_lossy())),
        }
    }
    if args.minimized && (args.once || args.console) {
        return Err("--minimized 不能与 --once 或 --console 同时使用".into());
    }
    if args.minimized && !cfg!(windows) {
        return Err("--minimized 仅支持 Windows".into());
    }
    Ok(args)
}

fn main() {
    let args = match parse_args(env::args_os().skip(1)) {
        Ok(args) => args,
        Err(message) => {
            attach_console();
            eprintln!("{message}\n{USAGE}");
            std::process::exit(2);
        }
    };
    if args.help {
        attach_console();
        print!("{USAGE}");
        return;
    }

    #[cfg(windows)]
    if !args.console && !args.once {
        let path = args.config_path.unwrap_or_else(|| {
            env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|p| p.join(CONFIG_FILE)))
                .unwrap_or_else(|| CONFIG_FILE.into())
        });
        if let Err(error) = windows_ui::run(path, args.minimized) {
            native_windows_gui::simple_message("校园网客户端启动失败", &error.to_string());
            std::process::exit(1);
        }
        return;
    }

    attach_console();
    let path = args.config_path.unwrap_or_else(|| CONFIG_FILE.into());
    let (_stop, receiver) = mpsc::channel();
    if let Err(error) = worker::run(&path, args.once, &receiver) {
        login::show_msg(&error);
        std::process::exit(1);
    }
}

fn attach_console() {
    #[cfg(windows)]
    unsafe {
        // 保留 shell 重定向的管道；只为没有有效标准句柄的双击/终端启动附加控制台。
        use winapi::um::{consoleapi::AttachConsole, processenv::GetStdHandle, winbase::STD_OUTPUT_HANDLE, wincon::ATTACH_PARENT_PROCESS};
        let stdout = GetStdHandle(STD_OUTPUT_HANDLE);
        if stdout.is_null() || stdout == winapi::um::handleapi::INVALID_HANDLE_VALUE {
            AttachConsole(ATTACH_PARENT_PROCESS);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(values: &[&str]) -> Result<Args, String> {
        parse_args(values.iter().map(std::ffi::OsString::from))
    }

    #[test]
    fn defaults_and_config_path() {
        let args = parse(&[]).unwrap();
        assert!(!args.once && !args.console && !args.minimized);
        assert!(args.config_path.is_none());
        let args = parse(&["--once", "-c", "含 空格/config.toml"]).unwrap();
        assert!(args.once);
        assert_eq!(args.config_path.unwrap(), PathBuf::from("含 空格/config.toml"));
    }

    #[test]
    fn invalid_arguments() {
        assert!(parse(&["--config"]).is_err());
        assert!(parse(&["--unknown"]).is_err());
        assert!(parse(&["--minimized", "--once"]).is_err());
        assert!(parse(&["--minimized", "--console"]).is_err());
        assert_eq!(parse(&["--minimized"]).is_ok(), cfg!(windows));
    }

    #[test]
    fn help_and_console() {
        assert!(parse(&["--help"]).unwrap().help);
        assert!(parse(&["--console"]).unwrap().console);
    }
}
