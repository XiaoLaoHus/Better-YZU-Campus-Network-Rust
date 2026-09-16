use std::error::Error;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// 可选网络服务的数量，对应 `login::SERVICE_LIST` 的长度
pub const SERVICE_COUNT: usize = 5;

/// 默认读取的配置文件名
pub const CONFIG_FILE: &str = "config.toml";

/// 配置模板文件名，用于在缺少 config.toml 时给出提示
pub const EXAMPLE_CONFIG_FILE: &str = "config.example.toml";

/// 用户配置。对应原 Python 脚本开头的 USER_ID / PASSWORD / SERVICE_INDEX，
/// 外加两个可选的高级配置项。
#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    /// 学工号 / 统一身份认证账号
    pub user_id: String,

    /// 校园网密码
    pub password: String,

    /// 网络服务索引，取值 1..=5
    pub service_index: usize,

    /// 重连检查间隔（秒）
    #[serde(default = "default_interval_secs")]
    pub interval_secs: u64,

    /// 是否跳过 TLS 证书校验，仅在网关使用自签证书时需要
    #[serde(default)]
    pub danger_accept_invalid_certs: bool,
}

fn default_interval_secs() -> u64 {
    600
}

#[cfg(windows)]
impl Default for Config {
    fn default() -> Self {
        Self {
            user_id: String::new(),
            password: String::new(),
            service_index: 1,
            interval_secs: default_interval_secs(),
            danger_accept_invalid_certs: false,
        }
    }
}

impl Config {
    /// Write a complete snapshot beside the destination, then atomically replace it.
    /// Never truncate the working configuration if serialization / writing fails.
    #[cfg(windows)]
    pub fn save(&self, path: &Path) -> Result<(), String> {
        use std::io::Write;
        use std::os::windows::ffi::OsStrExt;
        use std::time::{SystemTime, UNIX_EPOCH};
        use winapi::um::winbase::{MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH};

        self.validate().map_err(|error| error.to_string())?;
        let contents = toml::to_string_pretty(self).map_err(|_| "无法序列化配置。".to_owned())?;
        let stamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
        let name = path.file_name().ok_or("配置路径必须指向文件。")?;
        let mut temporary_name = name.to_os_string();
        temporary_name.push(format!(".{}.{}.tmp", std::process::id(), stamp));
        let temporary = path.with_file_name(temporary_name);
        let mut created = false;
        let result = (|| -> std::io::Result<()> {
            let mut file = fs::OpenOptions::new().write(true).create_new(true).open(&temporary)?;
            created = true;
            file.write_all(contents.as_bytes())?;
            file.sync_all()?;
            drop(file);
            let from: Vec<u16> = temporary.as_os_str().encode_wide().chain(Some(0)).collect();
            let to: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
            if unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) } == 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        })();
        if result.is_err() && created {
            let _ = fs::remove_file(&temporary);
        }
        // No TOML text or credentials in the error channel.
        result.map_err(|error| format!("保存失败：{error}。请检查配置目录是否存在且可写；原配置未改动。"))
    }

    /// 从指定路径读取并解析配置。
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();

        let contents = fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;

        toml::from_str(&contents).map_err(|source| ConfigError::Parse {
            path: path.to_path_buf(),
            source: Box::new(source),
        })
    }

    /// 校验配置是否可用。对应原脚本 `__main__` 里的 `all([USER_ID, PASSWORD, 1 <= SERVICE_INDEX <= 5])`。
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.user_id.trim().is_empty() || self.password.is_empty() {
            return Err(ConfigError::MissingCredentials);
        }

        if self.service_index == 0 || self.service_index > SERVICE_COUNT {
            return Err(ConfigError::InvalidServiceIndex(self.service_index));
        }

        if self.interval_secs == 0 {
            return Err(ConfigError::IntervalTooSmall);
        }

        Ok(())
    }
}

#[derive(Debug)]
pub enum ConfigError {
    /// 配置文件读不到（通常是不存在）
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    /// 配置文件存在但格式不对
    Parse {
        path: PathBuf,
        /// 装箱以免 `ConfigError` 过大触发 clippy::result_large_err
        source: Box<toml::de::Error>,
    },
    /// user_id 或 password 为空
    MissingCredentials,
    /// service_index 不在 1..=5 范围内
    InvalidServiceIndex(usize),
    /// interval_secs 为 0，会导致忙循环
    IntervalTooSmall,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Read { path, source } => write!(
                f,
                "无法读取配置文件 {}: {source}。请复制 {EXAMPLE_CONFIG_FILE} 为 {} 并填写你的信息。",
                path.display(),
                CONFIG_FILE
            ),
            ConfigError::Parse { path, .. } => {
                // toml 错误的 Display 会包含原始配置行，可能泄露密码。
                write!(f, "配置文件 {} 格式错误，请检查 TOML 语法和字段类型。", path.display())
            }
            ConfigError::MissingCredentials => write!(
                f,
                "请在 {CONFIG_FILE} 中填写您正确的 user_id 和 password。喂！等下我绝对说过了吧喵（？）"
            ),
            ConfigError::InvalidServiceIndex(index) => write!(
                f,
                "service_index 必须在 1 到 {SERVICE_COUNT} 之间，当前值为 {index}。"
            ),
            ConfigError::IntervalTooSmall => {
                write!(f, "interval_secs 必须大于 0。")
            }
        }
    }
}

impl Error for ConfigError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            ConfigError::Read { source, .. } => Some(source),
            ConfigError::Parse { source, .. } => Some(&**source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid() -> Config {
        toml::from_str("user_id = 'test-user'\npassword = 'test-password'\nservice_index = 1").unwrap()
    }

    #[test]
    fn defaults_and_valid_services() {
        let mut config = valid();
        assert_eq!(config.interval_secs, 600);
        assert!(!config.danger_accept_invalid_certs);
        for service in 1..=SERVICE_COUNT {
            config.service_index = service;
            assert!(config.validate().is_ok());
        }
    }

    #[test]
    fn rejects_invalid_configuration() {
        let mut config = valid();
        config.user_id = "  ".into();
        assert!(matches!(config.validate(), Err(ConfigError::MissingCredentials)));
        config = valid();
        config.password.clear();
        assert!(config.validate().is_err());
        config = valid();
        for service in [0, SERVICE_COUNT + 1] {
            config.service_index = service;
            assert!(matches!(config.validate(), Err(ConfigError::InvalidServiceIndex(_))));
        }
        config = valid();
        config.interval_secs = 0;
        assert!(matches!(config.validate(), Err(ConfigError::IntervalTooSmall)));
    }

    #[test]
    fn parse_error_does_not_display_credentials() {
        let source = toml::from_str::<Config>("password = secret-password").unwrap_err();
        let error = ConfigError::Parse { path: "config.toml".into(), source: Box::new(source) };
        assert!(!error.to_string().contains("secret-password"));
    }
}
