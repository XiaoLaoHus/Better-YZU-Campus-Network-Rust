use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

pub const NOTICE: &str = "当前软件仅为测试版，仍有很多问题，使用过程中可能出现异常。如遇到问题，请联系作者 QQ：2576381123。";
const ACKNOWLEDGED: &str = "beta_notice_acknowledged = true\n";

pub struct UiState {
    path: Option<PathBuf>,
}

impl UiState {
    pub fn load() -> Self {
        Self { path: std::env::var_os("LOCALAPPDATA").filter(|value| !value.is_empty())
            .map(|root| PathBuf::from(root).join("Better-YZU-Campus-Network").join("ui-state.toml")) }
    }

    pub fn acknowledged(&self) -> bool {
        self.path.as_ref().and_then(|path| fs::read_to_string(path).ok())
            .is_some_and(|text| text == ACKNOWLEDGED)
    }

    pub fn acknowledge(&self) -> io::Result<()> {
        let path = self.path.as_ref().ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "无法取得本地应用数据目录"))?;
        if let Some(parent) = path.parent() { fs::create_dir_all(parent)?; }
        // An interrupted write is treated as unconfirmed on the next launch.
        // This file is independent of the network configuration and contains no credentials.
        let mut file = fs::File::create(path)?;
        file.write_all(ACKNOWLEDGED.as_bytes())?;
        file.sync_all()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT: AtomicUsize = AtomicUsize::new(0);
    struct Directory(PathBuf);
    impl Directory {
        fn new() -> Self {
            let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
            let path = std::env::temp_dir().join(format!("yzu-state-{}-{stamp}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn state(&self) -> UiState { UiState { path: Some(self.0.join("app").join("ui-state.toml")) } }
    }
    impl Drop for Directory {
        fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
    }

    #[test]
    fn first_run_and_confirmation_survive_reload_without_touching_config() {
        let dir = Directory::new();
        let config = dir.0.join("config.toml");
        fs::write(&config, "private configuration").unwrap();
        assert!(!dir.state().acknowledged());
        dir.state().acknowledge().unwrap();
        assert!(dir.state().acknowledged());
        fs::rename(&config, dir.0.join("other-config.toml")).unwrap();
        assert!(dir.state().acknowledged());
        assert_eq!(fs::read_to_string(dir.0.join("other-config.toml")).unwrap(), "private configuration");
    }

    #[test]
    fn invalid_or_unreadable_state_is_not_confirmation() {
        let dir = Directory::new();
        let state = dir.state();
        state.acknowledge().unwrap();
        let path = state.path.as_ref().unwrap();
        for text in ["", "beta_notice_acknowledged = false\n", "invalid", "beta_notice_acknowledged = tru"] {
            fs::write(path, text).unwrap();
            assert!(!state.acknowledged());
        }
        fs::remove_file(path).unwrap();
        fs::create_dir(path).unwrap();
        assert!(!state.acknowledged());
        assert!(state.acknowledge().is_err());
    }

    #[test]
    fn missing_or_unwritable_directory_does_not_claim_success() {
        let state = UiState { path: None };
        assert!(!state.acknowledged());
        assert!(state.acknowledge().is_err());
        let dir = Directory::new();
        fs::write(dir.0.join("app"), "not a directory").unwrap();
        assert!(dir.state().acknowledge().is_err());
        assert!(!dir.state().acknowledged());
    }

    #[test]
    fn notice_contains_contact_and_beta_warning() {
        assert!(NOTICE.contains("测试版") && NOTICE.contains("很多问题") && NOTICE.contains("2576381123"));
        // Resolve only; loading state must never write to the user's profile.
        let _ = UiState::load();
    }
}
