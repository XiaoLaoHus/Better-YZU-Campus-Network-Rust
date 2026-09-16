use std::error::Error;
use std::fmt;
use std::time::Duration;

use reqwest::blocking::Client;
use reqwest::header::{
    HeaderMap, HeaderValue, ACCEPT, ACCEPT_LANGUAGE, CONTENT_TYPE, REFERER, REFERRER_POLICY,
};
use url::Url;

use crate::config::{Config, SERVICE_COUNT};

/// 可选网络服务，索引 1..=5 对应本数组的 0..=4
pub const SERVICE_LIST: [&str; SERVICE_COUNT] = [
    "学校互联网服务",
    "联通互联网服务",
    "移动互联网服务",
    "电信互联网服务",
    "校内免费服务",
];

/// SSO 入口 URL。其中的网关注册参数由校园网下发，解析逻辑与原 Python 脚本一致。
pub const YZU_INITIAL_URL: &str = "https://sso.yzu.edu.cn/login?service=http:%2F%2F10.245.2.20%2Feportal%2Findex.jsp%3Fwlanuserip%3D0b75e9537a715be3386d25c520fdb6a1%26wlanacname%3Deadf2f8586a293cce2e6336119a86ee6%26ssid%3D%26nasip%3Df48a0855dd4dc2a859a03f66e50cc495%26mac%3D538eb8468ee9b90a3a0ec1b08e9070ce%26t%3Dwireless-v2%26url%3D709db9dc9ce334aa02a9e1ee58ba6fcf3bc3349e947ead368bdd021b808fdbac30c65edaa96b0727";

const GET_TIMEOUT: Duration = Duration::from_secs(5);
const POST_TIMEOUT: Duration = Duration::from_secs(10);

/// 输出一条通知。原脚本的 `duration` 参数只用于控制横幅停留时间，本身未被使用，故删去。
pub fn show_msg(msg: &str) {
    println!("[通知] {msg}");
}

/// 打印启动/连接失败原因后退出。
pub fn show_msg_and_exit(msg: &str) -> ! {
    show_msg(msg);
    std::process::exit(1);
}

/// 构建全局共用的 HTTP 客户端。
///
/// `cookie_store(true)` 是必须的：原脚本用同一个 `httpx.Client` 先 GET 认证页、
/// 再 POST 登录，登录请求依赖 GET 阶段网关下发的会话 Cookie。
pub fn build_client(config: &Config) -> Result<Client, reqwest::Error> {
    let mut headers = HeaderMap::new();
    headers.insert(ACCEPT, HeaderValue::from_static("*/*"));
    headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("zh-CN,zh;q=0.9"));
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/x-www-form-urlencoded; charset=UTF-8"),
    );
    headers.insert(
        REFERRER_POLICY,
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );

    Client::builder()
        .cookie_store(true)
        .default_headers(headers)
        .danger_accept_invalid_certs(config.danger_accept_invalid_certs)
        .build()
}

/// 从 SSO 跳转中解析出的登录所需信息
struct RedirectInfo {
    /// 网关登录接口，形如 `http://{ip}/eportal/InterFace.do?method=login`
    login_url: String,
    /// 网关参数串，原样作为 `queryString` 字段提交
    query_string: String,
    /// 登录请求的 Referer
    referer: String,
}

/// 解析认证服务器信息。对应原脚本的 `get_redirect_info`。
fn get_redirect_info(client: &Client, initial_sso_url: &str) -> Result<RedirectInfo, LoginError> {
    show_msg("正在解析认证服务器信息...");

    let parsed = Url::parse(initial_sso_url)
        .map_err(|e| LoginError::Flow(format!("无法解析 SSO 入口 URL: {e}")))?;

    // `query_pairs` 会自动做百分号解码，等价于 Python 的 `urllib.parse.parse_qs`
    let new_url = parsed
        .query_pairs()
        .find(|(key, _)| key == "service")
        .map(|(_, value)| value.into_owned())
        .ok_or_else(|| {
            LoginError::Flow(
                "意外错误，请联系原作者github:https://github.com/GUMOUXUAN".to_string(),
            )
        })?;

    show_msg("正在获取参数desuwa...");

    let parsed_new_url = Url::parse(&new_url)
        .map_err(|e| LoginError::Flow(format!("无法解析跳转 URL: {e}")))?;

    let ip = parsed_new_url.host_str().unwrap_or_default();

    // 等价于原脚本的 `re.search(r"\?(.*)", new_url)`，此处无需引入 regex 依赖
    let query_string = new_url.split_once('?').map(|(_, query)| query);

    let (ip, query_string) = match (ip.is_empty(), query_string) {
        (false, Some(query)) => (ip, query),
        _ => {
            return Err(LoginError::Flow(format!(
                "无法从解析出的 URL 中提取 IP 或 QueryString。当前URL: {new_url}"
            )))
        }
    };

    let login_url = format!("http://{ip}/eportal/InterFace.do?method=login");

    // 与原脚本一致：先 GET 一次认证页，让网关下发会话 Cookie
    client
        .get(&new_url)
        .timeout(GET_TIMEOUT)
        .send()
        .map_err(LoginError::from_reqwest)?;

    Ok(RedirectInfo {
        login_url,
        query_string: query_string.to_string(),
        referer: new_url,
    })
}

/// 尝试登录一次。对应原脚本的 `login_attempt`。
///
/// 与 Python 版本一样，本函数把"业务失败"（索引越界、登录被拒、响应非 JSON）
/// 视作正常返回 `Ok(())`，只有真正需要提示用户的异常才走 `Err`。
pub fn login_attempt(client: &Client, config: &Config) -> Result<(), LoginError> {
    if config.service_index == 0 || config.service_index > SERVICE_COUNT {
        show_msg(&format!("服务索引必须在 1 到 {SERVICE_COUNT} 之间"));
        return Ok(());
    }

    let info = get_redirect_info(client, YZU_INITIAL_URL)?;

    show_msg("正在尝试登录...");

    let service = SERVICE_LIST[config.service_index - 1];

    // 手工编码表单体，而不是用 `RequestBuilder::form`：这样能沿用上面
    // `default_headers` 里那份 `charset=UTF-8` 的 Content-Type，避免出现重复头
    let body = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("userId", &config.user_id)
        .append_pair("password", &config.password)
        .append_pair("service", service)
        .append_pair("queryString", &info.query_string)
        .append_pair("operatorPwd", "")
        .append_pair("operatorUserId", "")
        .append_pair("validcode", "")
        .append_pair("passwordEncrypt", "")
        .finish();

    let referer = HeaderValue::from_str(&info.referer)
        .map_err(|e| LoginError::Unexpected(format!("非法的 Referer 头: {e}")))?;

    let res = client
        .post(&info.login_url)
        .header(REFERER, referer)
        .timeout(POST_TIMEOUT)
        .body(body)
        .send()
        .map_err(LoginError::from_reqwest)?;

    // 必须先取文本再解析：原脚本在 JSON 解析失败时会打印 `res.text` 帮助调试，
    // 因此不能直接消费响应体成 JSON
    let text = res.text().map_err(LoginError::from_reqwest)?;

    let res_json: serde_json::Value = match serde_json::from_str(&text) {
        Ok(value) => value,
        Err(_) => {
            show_msg("登录失败：服务器响应格式错误。可能原因：您正处于断网状态，且网关返回了非标准错误页面。");
            println!(
                "原始响应文本: {}",
                if text.is_empty() { "<EMPTY RESPONSE>" } else { &text }
            );
            return Ok(());
        }
    };

    match res_json.get("result").and_then(|value| value.as_str()) {
        Some("success") => show_msg("校园网成功连接了，Ciallo～(∠・ω< )～"),
        Some("fail") => {
            let message = res_json
                .get("message")
                .and_then(|value| value.as_str())
                .unwrap_or("未知错误");
            show_msg(&format!("登录失败: {message}"));
        }
        _ => show_msg(&format!("登录响应异常: {text}")),
    }

    Ok(())
}

#[derive(Debug)]
pub enum LoginError {
    /// 解析跳转参数失败。对应原脚本里显式抛出的 `ConnectionError`
    Flow(String),
    /// 网络连接错误。对应 `httpx.ConnectTimeout` / `httpx.ConnectError`
    Network(reqwest::Error),
    /// 其他意外错误
    Unexpected(String),
}

impl LoginError {
    /// 把 `reqwest::Error` 归类到 Network 或 Unexpected。
    fn from_reqwest(error: reqwest::Error) -> Self {
        if error.is_timeout() || error.is_connect() {
            LoginError::Network(error)
        } else {
            LoginError::Unexpected(error.to_string())
        }
    }
}

impl fmt::Display for LoginError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoginError::Flow(message) => write!(f, "{message}"),
            LoginError::Network(error) => {
                write!(f, "网络连接错误：可能未联网或服务器无响应。({error})")
            }
            LoginError::Unexpected(message) => write!(f, "{message}"),
        }
    }
}

impl Error for LoginError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            LoginError::Network(error) => Some(error),
            _ => None,
        }
    }
}
