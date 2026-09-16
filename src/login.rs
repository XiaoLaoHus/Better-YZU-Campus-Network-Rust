use std::error::Error;
use std::fmt;
use std::time::Duration;

use reqwest::blocking::Client;
use reqwest::header::{
    HeaderMap, HeaderValue, ACCEPT, ACCEPT_LANGUAGE, CONTENT_TYPE, LOCATION, REFERER,
    REFERRER_POLICY,
};
use reqwest::redirect::Policy;
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

/// 校园网 SSO 域名，用于从网关重定向地址里识别认证入口。
const SSO_HOST: &str = "sso.yzu.edu.cn";

/// 未认证时会被网关重定向的校园网门户根地址。
///
/// 会话参数（`wlanuserip`、`mac` 等）由网关按当次连接生成并做了私有加密，
/// 无法本地推算，只能在重定向链里现取；它们绑定具体设备，不适合硬编码进源码。
/// 未认证时访问门户，网关会一路重定向到 SSO 登录页，登录所需参数就在 SSO
/// 地址的 `service` 参数里。
const PORTAL_URL: &str = "http://10.245.2.20/";

/// 从门户根地址到 SSO 登录页最多跟随的重定向次数。
const MAX_REDIRECT_HOPS: usize = 3;

const GET_TIMEOUT: Duration = Duration::from_secs(5);
const POST_TIMEOUT: Duration = Duration::from_secs(10);
/// 探测超时要短于登录请求：它只是连通性检查，且会叠加在退出时的等待时间上。
const DETECT_TIMEOUT: Duration = Duration::from_secs(3);

/// 输出到控制台，或 Windows 窗口的有界日志队列。
pub fn show_msg(msg: &str) {
    crate::logging::message(msg);
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

/// 从重定向地址中识别 SSO 登录入口。
///
/// 未认证时网关把请求重定向到 SSO 登录页（含 `service` 参数）；已认证时重定向到
/// 门户的成功页，此时返回 `None`。
fn sso_url_from_location(location: &str) -> Option<String> {
    let parsed = Url::parse(location).ok()?;
    let is_sso_host = parsed.host_str() == Some(SSO_HOST);
    let has_service = parsed.query_pairs().any(|(key, _)| key == "service");
    if is_sso_host || has_service {
        Some(location.to_string())
    } else {
        None
    }
}

/// 顺着网关的重定向链取回本次会话的 SSO 入口地址。
///
/// 返回 `Ok(None)` 表示网关有响应但没有给出认证入口，也就是当前已在线。
fn discover_sso_url(client: &Client) -> Result<Option<String>, LoginError> {
    // 从门户根地址出发，跟着网关的重定向链（门户页 → SSO 登录页）找到 SSO 入口。
    let mut current = PORTAL_URL.to_string();
    let mut responded = false;
    let mut last_error = None;

    for _ in 0..MAX_REDIRECT_HOPS {
        match client.get(&current).timeout(DETECT_TIMEOUT).send() {
            Ok(response) => {
                responded = true;
                let location = response
                    .headers()
                    .get(LOCATION)
                    .and_then(|value| value.to_str().ok());
                match location {
                    Some(loc) => {
                        if let Some(sso_url) = sso_url_from_location(loc) {
                            return Ok(Some(sso_url));
                        }
                        // 网关可能先跳到门户页（index.jsp），再跳到 SSO：跟一步。
                        current = loc.to_string();
                    }
                    // 没有重定向：当前已在线或已认证，没有认证入口。
                    None => return Ok(None),
                }
            }
            Err(error) => {
                last_error = Some(LoginError::from_reqwest(error));
                break;
            }
        }
    }

    if responded {
        Ok(None)
    } else {
        Err(last_error.unwrap_or_else(|| LoginError::Unexpected("无法探测网关".to_string())))
    }
}

/// 探测专用的客户端：必须关闭重定向跟随，否则读不到网关下发的 `Location`。
fn build_detect_client() -> Result<Client, LoginError> {
    Client::builder()
        .redirect(Policy::none())
        .build()
        .map_err(|error| LoginError::Unexpected(format!("无法创建探测客户端: {error}")))
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

    // 会话参数每次现取，源码里不再保留任何个人设备信息。
    let Some(sso_url) = discover_sso_url(&build_detect_client()?)? else {
        show_msg("当前已在线或未接入校园网，跳过本次登录。");
        return Ok(());
    };

    let info = get_redirect_info(client, &sso_url)?;

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

    // 先获取响应文本，再解析网关 JSON；原始响应不写入日志，避免泄露认证信息。
    let text = res.text().map_err(LoginError::from_reqwest)?;

    let res_json: serde_json::Value = match serde_json::from_str(&text) {
        Ok(value) => value,
        Err(_) => {
            show_msg("登录失败：服务器响应格式错误。可能原因：您正处于断网状态，且网关返回了非标准错误页面。");
            // 原始响应可能包含认证信息，不写入 GUI 或控制台日志。
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
        _ => show_msg("登录响应异常：缺少有效的 result 字段。"),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_sso_entry_from_redirect_location() {
        let sso =
            "https://sso.yzu.edu.cn/login?service=http%3A%2F%2F10.245.2.20%2Feportal%2Findex.jsp";
        assert_eq!(sso_url_from_location(sso).as_deref(), Some(sso));
        assert!(sso_url_from_location("https://sso.yzu.edu.cn/login").is_some());
        // 网关也可能把认证页放在别的域名下，靠 service 参数识别
        assert!(sso_url_from_location("http://gw.example/auth?service=eportal").is_some());
    }

    #[test]
    fn ignores_redirects_that_are_not_the_auth_entry() {
        // 已认证时网关重定向到门户成功页，不是认证入口
        let success_page = "http://10.245.2.20/eportal/redirectortosuccess.jsp";
        assert!(sso_url_from_location(success_page).is_none());
        assert!(sso_url_from_location("").is_none());
        assert!(sso_url_from_location("不是合法的 URL").is_none());
    }
}
