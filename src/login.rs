use std::error::Error;
use std::fmt;
use std::io::Read;
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

/// 校园网门户主机（同时用于校验登录请求的去向）。
const PORTAL_HOST: &str = "10.245.2.20";

/// 会话参数特征。
///
/// 连接校园网时系统会弹出一个认证网页，**页面的地址本身就带着全部会话参数**
/// （`wlanuserip`、`mac`、`nasip` 等）。这条特征用来把它和 SSO 登录页区分开：
/// 前者参数就在地址里，后者参数藏在 `service` 参数内。
const SESSION_MARKER: &str = "wlanuserip";

/// 探测地址，按顺序尝试，命中即止。
///
/// 会话参数（`wlanuserip`、`mac` 等）由网关按当次连接生成并做了私有加密，
/// 无法本地推算，只能在重定向链里现取；它们绑定具体设备，不适合硬编码进源码。
///
/// 顺序依据 2026-09-16 的校园网实测调整：
/// - 门户主机可达，且确实会下发网关自己的跳转，放在最前；
/// - `www.baidu.com` 在该网络下 DNS 解析失败（请求还没发出就报错），
///   所以外网探测必须备一个 IP 字面量地址，域名只作为兜底。
///
/// 外网地址必须是 HTTP：HTTPS 无法被网关重定向。
const PROBE_URLS: [&str; 3] = [PORTAL_PROBE, EXTERNAL_IP_PROBE, EXTERNAL_DNS_PROBE];

/// 校园网门户根地址，网关必然可达。
const PORTAL_PROBE: &str = "http://10.245.2.20/";

/// 外网探测：IP 字面量，不需要 DNS。
const EXTERNAL_IP_PROBE: &str = "http://223.5.5.5/";

/// 外网探测：域名，依赖 DNS，实测在未认证时可能解析失败。
const EXTERNAL_DNS_PROBE: &str = "http://www.baidu.com/";

/// 网关表示「已认证」的成功页路径特征。
const ONLINE_HINT: &str = "redirectortosuccess";

/// 无跳转时最多读取多少响应正文用于查找认证入口。
///
/// 实测网关可能返回 200 加一个内嵌认证链接的门户兜底页，入口只能从正文里找；
/// 但正文可能很大（真实外网站点），只读开头即可。
const MAX_BODY_BYTES: u64 = 32 * 1024;

/// 单次探测最多跟随的重定向次数。
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

/// 把地址脱敏成可以安全写进日志的形式：保留协议、主机、路径和参数**名**。
///
/// 网关下发的 `Location` 里 `mac`、`wlanuserip` 等是个人数据，值一律不写日志。
fn redact(url: &str) -> String {
    let Ok(parsed) = Url::parse(url) else {
        return "<无法解析的地址>".to_string();
    };
    // 显式拼装，不依赖 `Position` 切片的取址细节（`BeforeQuery` 实际含 `?`）。
    let mut text = format!("{}://{}", parsed.scheme(), parsed.host_str().unwrap_or_default());
    if let Some(port) = parsed.port() {
        text.push_str(&format!(":{port}"));
    }
    text.push_str(parsed.path());

    let names: Vec<String> = parsed.query_pairs().map(|(key, _)| key.into_owned()).collect();
    if !names.is_empty() {
        text.push_str(&format!("?[{}]", names.join(",")));
    }
    text
}

/// 判断主机是否是校园网内网的私有 IPv4 地址。
///
/// 登录请求会把密码发往这个主机，因此只接受私有地址，避免被伪造成认证入口的
/// 外部主机骗走凭据。
fn is_private_host(host: &str) -> bool {
    host.parse::<std::net::Ipv4Addr>().is_ok_and(|ip| ip.is_private())
}

/// 把 `Location` 头解析成绝对地址。网关可能下发相对路径（如 `/eportal/index.jsp`），
/// 必须按当前地址补齐，否则下一次请求会拿到非法地址。
fn resolve_location(base: &str, location: &str) -> Option<String> {
    Url::parse(base).ok()?.join(location).ok().map(|url| url.to_string())
}

/// 地址本身是否就是「带会话参数的门户页地址」。
///
/// SSO 登录页的 `service` 参数里也会出现同样这些参数名（百分号编码不影响字母），
/// 所以要一并排除，避免把 SSO 页误判成门户页。
fn is_session_url(url: &str) -> bool {
    url.contains(SESSION_MARKER) && !url.contains(SSO_HOST)
}

/// 识别可用的认证入口，返回原地址。
///
/// 实测入口有两种形态，都在这里统一认下：
/// - **SSO 登录页**：未认证时网关把请求重定向过去，参数藏在 `service` 里；
/// - **门户页地址**：连接校园网时系统弹出的那个认证网页，参数就在地址本身。
///
/// 已认证时重定向目标是门户成功页，两种都不匹配，返回 `None`。
fn entry_from_url(url: &str) -> Option<String> {
    let parsed = Url::parse(url).ok()?;
    if parsed.host_str() == Some(SSO_HOST) {
        return Some(url.to_string());
    }

    // 认证页也可能挂在别的域名下，此时以 `service` 参数指向门户为准
    let points_to_portal = parsed
        .query_pairs()
        .find(|(key, _)| key == "service")
        .and_then(|(_, value)| Url::parse(&value).ok())
        .is_some_and(|target| target.host_str() == Some(PORTAL_HOST));
    if points_to_portal {
        return Some(url.to_string());
    }

    // 门户页地址：只认内网主机，否则一个外网页面上的同名参数就能把密码引出去
    if is_session_url(url) && parsed.host_str().is_some_and(is_private_host) {
        return Some(url.to_string());
    }

    None
}

/// 探测结果。
///
/// 区分「已在线」和「没找到入口」两种落空情况，是为了给出准确的提示：
/// 前者无需处理，后者往往说明探测方式对该网络不适用。
enum Discovery {
    /// 拿到认证入口
    Entry(String),
    /// 网关明确表示已认证
    Online,
    /// 网关有响应，但没有认证入口，也没看到成功页
    NoEntry,
}

/// 在文本里切出围绕首个 `marker` 出现的那个地址。
///
/// 有些网关不用 302，而是返回 200 加一个内嵌认证链接的门户兜底页，此时入口
/// 只能从正文里取。正文里的查询参数是 HTML 转义的（`&amp;`），取出后必须还原，
/// 否则拼进 `queryString` 的参数会错。
fn url_around(text: &str, marker: &str) -> Option<String> {
    let start = text.find(marker)?;

    // 向前回溯到 URL 起点：上一个分隔符之后。分隔符只取单字节字符，
    // 避免在多字节字符中间切片。
    const DELIMITERS: [char; 8] = ['"', '\'', '(', ')', '<', '>', ' ', '\n'];
    let begin = text[..start]
        .rfind(DELIMITERS)
        .map_or(0, |index| index + 1);

    // 向后找到 URL 结束：下一个分隔符之前
    let tail = &text[start..];
    let end = tail.find(DELIMITERS).unwrap_or(tail.len());

    let candidate = &text[begin..start + end];
    // 协议相对地址（`//host/path`）协议头要补齐
    if candidate.starts_with("//") {
        return Some(format!("https:{candidate}").replace("&amp;", "&"));
    }
    if !candidate.starts_with("http") {
        return None;
    }
    Some(candidate.replace("&amp;", "&"))
}

/// 从响应正文里找出首个可用认证入口。
///
/// 依次按 SSO 域名、会话参数特征定位，返回第一个能通过 `entry_from_url` 的地址。
fn auth_url_from_text(text: &str) -> Option<String> {
    [SSO_HOST, SESSION_MARKER]
        .into_iter()
        .find_map(|marker| url_around(text, marker).filter(|url| entry_from_url(url).is_some()))
}

/// 顺着网关的重定向链取回本次会话的认证入口。
fn discover_entry(client: &Client) -> Result<Discovery, LoginError> {
    let mut responded = false;
    let mut saw_online_hint = false;
    let mut last_error = None;

    for probe in PROBE_URLS {
        let mut current = probe.to_string();

        for _ in 0..MAX_REDIRECT_HOPS {
            show_msg(&format!("探测 {} ...", redact(&current)));

            let response = match client.get(&current).timeout(DETECT_TIMEOUT).send() {
                Ok(response) => response,
                Err(error) => {
                    let error = LoginError::from_reqwest(error);
                    show_msg(&format!("  无法连接：{error}"));
                    last_error = Some(error);
                    break;
                }
            };
            responded = true;

            let status = response.status().as_u16();
            // 取成拥有所有权的字符串，后面读正文需要移动 response
            let location = response
                .headers()
                .get(LOCATION)
                .and_then(|value| value.to_str().ok())
                .map(str::to_string);

            let Some(location) = location else {
                // 网关可能不用 302：实测它直接返回 200 加一个门户兜底页，
                // 认证入口只能在正文里找。
                let content_type = response
                    .headers()
                    .get(CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or("未知类型")
                    .to_string();

                let mut buffer = Vec::new();
                // 读超时也保留已读到的部分，不影响后续判断
                let _ = response.take(MAX_BODY_BYTES).read_to_end(&mut buffer);
                let body = String::from_utf8_lossy(&buffer);
                show_msg(&format!(
                    "  HTTP {status}，无跳转（{content_type}，{} 字节）",
                    buffer.len()
                ));

                if let Some(url) = auth_url_from_text(&body) {
                    show_msg(&format!("  正文中找到认证入口 → {}", redact(&url)));
                    return Ok(Discovery::Entry(url));
                }
                // 有链接但用不上：把地址脱敏后打出来，方便对着排查
                if let Some(url) = url_around(&body, SESSION_MARKER)
                    .or_else(|| url_around(&body, SSO_HOST))
                {
                    show_msg(&format!("  正文中的链接不可用，已忽略 → {}", redact(&url)));
                }
                break;
            };

            // 网关可能下发相对路径，必须按当前地址解析成绝对地址再跟下一步，
            // 否则下一轮请求会因为拿到非法地址而直接失败、链路断掉。
            let Some(next) = resolve_location(&current, &location) else {
                show_msg(&format!("  HTTP {status}，跳转地址无法解析"));
                break;
            };
            show_msg(&format!("  HTTP {status}，跳转 → {}", redact(&next)));

            if entry_from_url(&next).is_some() {
                show_msg("找到认证入口，正在获取本次会话参数...");
                return Ok(Discovery::Entry(next));
            }
            if next.contains(ONLINE_HINT) {
                show_msg("  网关返回认证成功页，判断为已在线");
                saw_online_hint = true;
            }
            current = next;
        }
    }

    if !responded {
        let error = last_error.unwrap_or_else(|| LoginError::Unexpected("无法探测网关".to_string()));
        return Err(error);
    }

    Ok(if saw_online_hint { Discovery::Online } else { Discovery::NoEntry })
}

/// 探测专用的客户端：必须关闭重定向跟随，否则读不到网关下发的 `Location`。
fn build_detect_client() -> Result<Client, LoginError> {
    Client::builder()
        .redirect(Policy::none())
        .build()
        .map_err(|error| LoginError::Unexpected(format!("无法创建探测客户端: {error}")))
}

/// 从认证入口里取出「带会话参数的门户地址」。
///
/// 入口有两种形态，统一成后者再交给 `get_redirect_info`：
/// - SSO 登录页：会话参数在 `service` 参数里；
/// - 门户页地址：连接校园网时浏览器被弹到的那个页面，参数就在地址本身。
fn service_url_from_entry(entry: &str) -> Result<String, LoginError> {
    // 入口本身就是弹窗页地址：参数已经在地址里，直接用
    if is_session_url(entry) {
        return Ok(entry.to_string());
    }

    // `query_pairs` 会自动做百分号解码，等价于 Python 的 `urllib.parse.parse_qs`
    let parsed =
        Url::parse(entry).map_err(|e| LoginError::Flow(format!("无法解析认证入口 URL: {e}")))?;

    parsed
        .query_pairs()
        .find(|(key, _)| key == "service")
        .map(|(_, value)| value.into_owned())
        .ok_or_else(|| {
            LoginError::Flow(
                "意外错误，请联系原作者github:https://github.com/GUMOUXUAN".to_string(),
            )
        })
}

/// 解析认证服务器信息。对应原脚本的 `get_redirect_info`。
fn get_redirect_info(client: &Client, new_url: &str) -> Result<RedirectInfo, LoginError> {
    show_msg("正在解析认证服务器信息...");
    show_msg("正在获取参数desuwa...");

    let parsed_new_url =
        Url::parse(new_url).map_err(|e| LoginError::Flow(format!("无法解析跳转 URL: {e}")))?;

    let ip = parsed_new_url.host_str().unwrap_or_default();

    // 等价于原脚本的 `re.search(r"\?(.*)", new_url)`，此处无需引入 regex 依赖
    let query_string = new_url.split_once('?').map(|(_, query)| query);

    let (ip, query_string) = match (ip.is_empty(), query_string) {
        (false, Some(query)) => (ip, query),
        _ => {
            // 地址里含个人参数，写日志前先脱敏。
            return Err(LoginError::Flow(format!(
                "无法从解析出的 URL 中提取 IP 或 QueryString。当前URL: {}",
                redact(new_url)
            )));
        }
    };

    // 下面会把密码 POST 到这个主机，只允许校园网私有地址，
    // 否则一个伪造的跳转就能把凭据引到外部服务器。
    if !is_private_host(ip) {
        return Err(LoginError::Flow(format!(
            "认证服务器地址 {ip} 不是校园网内网地址，已中止以避免泄露账号密码。"
        )));
    }

    let login_url = format!("http://{ip}/eportal/InterFace.do?method=login");

    // 与原脚本一致：先 GET 一次认证页，让网关下发会话 Cookie
    client
        .get(new_url)
        .timeout(GET_TIMEOUT)
        .send()
        .map_err(LoginError::from_reqwest)?;

    Ok(RedirectInfo {
        login_url,
        query_string: query_string.to_string(),
        referer: new_url.to_string(),
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
    let entry = match discover_entry(&build_detect_client()?)? {
        Discovery::Entry(entry) => entry,
        Discovery::Online => {
            show_msg("当前已在线，跳过本次登录。");
            return Ok(());
        }
        Discovery::NoEntry => {
            // 与「已在线」分开提示：这种情况往往说明探测方式对该网络不适用，
            // 上面的探测日志是排查依据。
            show_msg("未能从网关取到认证入口，跳过本次登录。若你确实处于断网状态，请保留上面的探测日志以便排查。");
            return Ok(());
        }
    };

    // 弹窗页地址直接就是参数串；SSO 入口则还要把 `service` 参数解出来。
    // 统一成「带会话参数的门户地址」再交给下面解析。
    let service_url = service_url_from_entry(&entry)?;
    let info = get_redirect_info(client, &service_url)?;

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
        assert_eq!(entry_from_url(sso).as_deref(), Some(sso));
        assert!(entry_from_url("https://sso.yzu.edu.cn/login").is_some());
        // 认证页也可能挂在别的域名下，此时以 service 参数指向门户为准
        let other_host = "http://gw.example/auth?service=http%3A%2F%2F10.245.2.20%2Feportal";
        assert!(entry_from_url(other_host).is_some());
    }

    #[test]
    fn detects_portal_page_url_as_entry() {
        // 连接校园网时弹出的认证页：会话参数就在地址本身，不需要再解 service
        let popup = "http://10.245.2.20/eportal/index.jsp?wlanuserip=SECRET&wlanacname=x&ssid=&nasip=y&mac=SECRETMAC&t=wireless-v2&url=z";
        assert_eq!(entry_from_url(popup).as_deref(), Some(popup));
        assert_eq!(service_url_from_entry(popup).unwrap(), popup);
        // SSO 页的 service 参数里也含同样的参数名，不能被误判成门户页
        let sso = "https://sso.yzu.edu.cn/login?service=http%3A%2F%2F10.245.2.20%2Feportal%2Findex.jsp%3Fwlanuserip%3DSECRET";
        assert!(!is_session_url(sso));
        assert_eq!(
            service_url_from_entry(sso).unwrap(),
            "http://10.245.2.20/eportal/index.jsp?wlanuserip=SECRET"
        );
        // 外网页面上的同名参数不认：否则密码会被引到外部主机
        assert!(entry_from_url("http://evil.example/x?wlanuserip=1").is_none());
    }

    #[test]
    fn ignores_redirects_that_are_not_the_auth_entry() {
        // 已认证时网关重定向到门户成功页，不是认证入口
        let success_page = "http://10.245.2.20/eportal/redirectortosuccess.jsp";
        assert!(entry_from_url(success_page).is_none());
        assert!(entry_from_url("").is_none());
        assert!(entry_from_url("不是合法的 URL").is_none());
        // 外网地址即便带 service 参数也不算认证入口：否则一个伪造的跳转
        // 就能把密码引到外部主机
        let hostile = "http://evil.example/login?service=http%3A%2F%2Fevil.example%2F";
        assert!(entry_from_url(hostile).is_none());
    }

    #[test]
    fn finds_portal_page_url_in_response_body() {
        // 有些网关不做跳转，直接把认证页正文返回来，地址在正文里
        let body = r#"<html><script>window.location.href="http://10.245.2.20/eportal/index.jsp?wlanuserip=SECRET&mac=SECRETMAC";</script></html>"#;
        let url = auth_url_from_text(body).expect("应从正文中取到入口");
        assert!(url.starts_with("http://10.245.2.20/eportal/index.jsp?"));
        assert!(service_url_from_entry(&url).is_ok());
    }

    #[test]
    fn resolves_relative_redirect_targets() {
        // 网关下发相对路径时，必须按当前地址补齐，否则重定向链会断掉
        assert_eq!(
            resolve_location("http://10.245.2.20/", "/eportal/index.jsp").as_deref(),
            Some("http://10.245.2.20/eportal/index.jsp")
        );
        // 绝对地址原样保留
        let absolute = "https://sso.yzu.edu.cn/login?service=x";
        assert_eq!(resolve_location("http://10.245.2.20/", absolute).as_deref(), Some(absolute));
        // 基准地址本身非法时不应panic
        assert!(resolve_location("不是合法的地址", "/a").is_none());
    }

    #[test]
    fn redacts_personal_parameters_from_log_output() {
        let with_secrets = "http://10.245.2.20/eportal/index.jsp?wlanuserip=SECRETIP&mac=SECRETMAC";
        let safe = redact(with_secrets);
        assert_eq!(safe, "http://10.245.2.20/eportal/index.jsp?[wlanuserip,mac]");
        assert!(!safe.contains("SECRETIP"));
        assert!(!safe.contains("SECRETMAC"));
        // 无参数时保持原样
        assert_eq!(redact("http://10.245.2.20/"), "http://10.245.2.20/");
        // 带端口时端口要保留，且不能多出一个 `?`
        assert_eq!(redact("http://10.245.2.20:8080/a?x=1"), "http://10.245.2.20:8080/a?[x]");
        assert_eq!(redact("不是合法的地址"), "<无法解析的地址>");
    }

    #[test]
    fn only_accepts_private_hosts_for_login() {
        // 校园网门户是私有地址，可以发凭据
        assert!(is_private_host("10.245.2.20"));
        assert!(is_private_host("192.168.1.1"));
        // 公网地址和域名一律拒绝，避免密码被发到外部主机
        assert!(!is_private_host("8.8.8.8"));
        assert!(!is_private_host("evil.example"));
        assert!(!is_private_host(""));
    }

    #[test]
    fn extracts_sso_entry_from_portal_page_body() {
        // 网关不用 302 时，认证入口只在正文里
        let body = r#"<html><a href="https://sso.yzu.edu.cn/login?service=http%3A%2F%2F10.245.2.20%2Feportal%2Findex.jsp">登录</a></html>"#;
        let url = auth_url_from_text(body).expect("应从正文中取到入口");
        assert!(url.starts_with("https://sso.yzu.edu.cn/login?service="));
        assert!(entry_from_url(&url).is_some());
    }

    #[test]
    fn unescapes_html_entities_in_body_url() {
        // 正文里的查询参数是 HTML 转义的，取出后要还原，否则参数会被拼错
        let body = r#"<a href="https://sso.yzu.edu.cn/login?service=http%3A%2F%2F10.245.2.20%2F&amp;t=wireless-v2">x</a>"#;
        let url = auth_url_from_text(body).expect("应从正文中取到入口");
        assert!(!url.contains("&amp;"));
        assert!(url.contains("&t=wireless-v2"));
    }

    #[test]
    fn ignores_body_without_a_usable_sso_link() {
        assert!(auth_url_from_text("<html>普通页面</html>").is_none());
        // 出现 SSO 域名但不是地址形式时不应误判
        assert!(auth_url_from_text("联系 sso.yzu.edu.cn 管理员").is_none());
    }
}
