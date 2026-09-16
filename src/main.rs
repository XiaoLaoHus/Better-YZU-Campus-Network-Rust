mod config;
mod login;

use std::env;
use std::thread;
use std::time::Duration;

use config::{Config, CONFIG_FILE};
use login::{build_client, login_attempt, show_msg, show_msg_and_exit, LoginError};

const USAGE: &str = "\
用法: better-yzu-campus-network [选项]

选项:
  -c, --config <路径>  指定配置文件路径（默认为 ./config.toml）
      --once           只尝试登录一次后退出，供 CI 与调试使用
  -h, --help           显示本帮助
";

struct Args {
    once: bool,
    config_path: String,
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        once: false,
        config_path: CONFIG_FILE.to_string(),
    };

    let mut iter = env::args().skip(1);

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--once" => args.once = true,
            "-c" | "--config" => {
                let path = iter.next().ok_or_else(|| format!("{arg} 需要一个参数"))?;
                args.config_path = path;
            }
            "-h" | "--help" => {
                print!("{USAGE}");
                std::process::exit(0);
            }
            other => return Err(format!("未知参数: {other}")),
        }
    }

    Ok(args)
}

fn main() {
    let args = match parse_args() {
        Ok(args) => args,
        Err(message) => {
            eprintln!("{message}");
            eprint!("{USAGE}");
            std::process::exit(2);
        }
    };

    let config = match Config::load(&args.config_path) {
        Ok(config) => config,
        Err(error) => show_msg_and_exit(&error.to_string()),
    };

    if let Err(error) = config.validate() {
        show_msg_and_exit(&error.to_string());
    }

    show_msg("启动了喵...困困困喵");

    let client = match build_client(&config) {
        Ok(client) => client,
        Err(error) => show_msg_and_exit(&format!("无法创建 HTTP 客户端: {error}")),
    };

    loop {
        match login_attempt(&client, &config) {
            Ok(()) => {}
            Err(LoginError::Flow(message)) => show_msg(&format!("流程错误: {message}")),
            Err(LoginError::Network(error)) => show_msg(&error.to_string()),
            Err(error @ LoginError::Unexpected(_)) => {
                eprintln!("发生意外错误: {error}");
                show_msg("发生意外错误，请检查控制台。");
            }
        }

        if args.once {
            return;
        }

        thread::sleep(Duration::from_secs(config.interval_secs));
    }
}
