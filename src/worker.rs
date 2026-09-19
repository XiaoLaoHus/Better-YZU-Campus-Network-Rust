use std::path::Path;
use std::sync::mpsc::{Receiver, RecvTimeoutError, TryRecvError};
use std::time::Duration;

use crate::config::Config;
use crate::login::{login_attempt, show_msg, Gateway};

fn wait_for_stop(stop: &Receiver<()>, interval: Duration) -> bool {
    !matches!(stop.recv_timeout(interval), Err(RecvTimeoutError::Timeout))
}

pub fn run(path: &Path, once: bool, stop: &Receiver<()>) -> Result<(), String> {
    let config = Config::load(path).map_err(|error| error.to_string())?;
    run_config(config, once, stop)
}

/// GUI passes the saved snapshot so a later file edit cannot change a queued restart.
pub fn run_config(config: Config, once: bool, stop: &Receiver<()>) -> Result<(), String> {
    config.validate().map_err(|error| error.to_string())?;
    crate::logging::set_secrets(&config.user_id, &config.password);
    // 版本号写进日志：用户贴出来的日志必须能一眼看清是哪个构建，
    // 否则排查时无法确认「这个现象对应这份代码」。
    show_msg(&format!("启动了喵...困困困喵（v{}）", env!("CARGO_PKG_VERSION")));
    let mut gateway = Gateway::new(&config)?;

    loop {
        if !matches!(stop.try_recv(), Err(TryRecvError::Empty)) {
            return Ok(());
        }
        if let Err(error) = login_attempt(&mut gateway, &config) {
            show_msg(&error.to_string());
        }
        if once {
            return Ok(());
        }
        show_msg(&format!("等待 {} 秒后再次尝试，隐藏窗口不影响后台运行。", config.interval_secs));
        if wait_for_stop(stop, Duration::from_secs(config.interval_secs)) {
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    #[test]
    fn queued_stop_interrupts_long_interval() {
        let (sender, receiver) = mpsc::channel();
        sender.send(()).unwrap();
        assert!(wait_for_stop(&receiver, Duration::from_secs(600)));
    }

    #[test]
    fn disconnected_controller_stops_worker() {
        let (sender, receiver) = mpsc::channel();
        drop(sender);
        assert!(wait_for_stop(&receiver, Duration::from_secs(600)));
    }

    #[test]
    fn timeout_allows_next_attempt() {
        let (_sender, receiver) = mpsc::channel();
        assert!(!wait_for_stop(&receiver, Duration::ZERO));
    }
}
