use std::cell::RefCell;
#[cfg(any(windows, test))]
use std::collections::VecDeque;
use std::sync::mpsc::SyncSender;

const MAX_MESSAGE_CHARS: usize = 2048;
#[cfg(any(windows, test))]
pub const MAX_LOG_LINES: usize = 200;

#[derive(Default)]
struct Output {
    sender: Option<SyncSender<String>>,
    secrets: Vec<String>,
}

thread_local! {
    static OUTPUT: RefCell<Output> = RefCell::new(Output::default());
}

#[cfg(windows)]
pub fn set_sender(sender: SyncSender<String>) {
    OUTPUT.with(|output| output.borrow_mut().sender = Some(sender));
}

pub fn set_secrets(user_id: &str, password: &str) {
    OUTPUT.with(|output| {
        output.borrow_mut().secrets = [user_id, password]
            .into_iter()
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .collect();
    });
}

pub fn message(message: &str) {
    OUTPUT.with(|output| {
        let output = output.borrow();
        let mut text = message.to_owned();
        for secret in &output.secrets {
            text = text.replace(secret, "[已隐藏]");
        }
        let text: String = text.chars().take(MAX_MESSAGE_CHARS).collect();
        if let Some(sender) = &output.sender {
            // UI 关闭或忙碌时不能阻塞联网线程，也不能无限累积日志。
            let _ = sender.try_send(text);
        } else {
            println!("[通知] {text}");
        }
    });
}

#[cfg(any(windows, test))]
#[derive(Default)]
pub struct LogBuffer(VecDeque<String>);

#[cfg(any(windows, test))]
impl LogBuffer {
    pub fn push(&mut self, message: &str) {
        for line in message.lines() {
            if self.0.len() == MAX_LOG_LINES {
                self.0.pop_front();
            }
            self.0.push_back(line.chars().take(MAX_MESSAGE_CHARS).collect());
        }
    }

    pub fn text(&self) -> String {
        self.0.iter().cloned().collect::<Vec<_>>().join("\r\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_history_is_bounded_including_multiline_messages() {
        let mut log = LogBuffer::default();
        for n in 0..MAX_LOG_LINES + 10 {
            log.push(&n.to_string());
        }
        assert_eq!(log.0.len(), MAX_LOG_LINES);
        assert_eq!(log.0.front().unwrap(), "10");
        log.push("one\ntwo");
        assert!(log.text().ends_with("one\r\ntwo"));
        log.push(&"长".repeat(MAX_MESSAGE_CHARS + 1));
        assert_eq!(log.0.back().unwrap().chars().count(), MAX_MESSAGE_CHARS);
    }

    #[test]
    fn credentials_are_redacted_and_full_channel_does_not_block() {
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        OUTPUT.with(|output| output.borrow_mut().sender = Some(sender));
        set_secrets("test-user", "test-password");
        message("test-user: test-password");
        message("dropped because the channel is full");
        assert_eq!(receiver.recv().unwrap(), "[已隐藏]: [已隐藏]");
        OUTPUT.with(|output| *output.borrow_mut() = Output::default());
    }
}
