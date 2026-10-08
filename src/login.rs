use std::error::Error;
use std::fmt;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
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

/// 手动输入的 SSO 登录地址使用的域名。
const SSO_HOST: &str = "sso.yzu.edu.cn";
const GET_TIMEOUT: Duration = Duration::from_secs(5);
const POST_TIMEOUT: Duration = Duration::from_secs(10);
/// 认证响应的读取上限。
const MAX_BODY_BYTES: u64 = 32 * 1024;

/// 自实现 HTTP 路径用的 User-Agent。
///
/// **只给绕开 reqwest 的那条路用，不设进 reqwest 客户端。**
/// v2.0.2 曾把浏览器 UA 和一组浏览器 Accept 头塞进 reqwest 客户端，理由是
/// 「网关可能掐掉不像浏览器的流量」；v2.0.3、v2.0.4 的实测把这条否掉了：
/// 加与不加这些头，reqwest 的结果一模一样。所以它只出现在亲手写的请求里。
const USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";

/// 自实现 HTTP 路径的登录请求超时。
const RAW_TIMEOUT: Duration = Duration::from_secs(10);

/// 自实现 HTTP 路径最多读多少字节，防对端不关连接时把内存读爆。
const MAX_RAW_BYTES: usize = 64 * 1024;

/// 输出到控制台，或 Windows 窗口的有界日志队列。
pub fn show_msg(msg: &str) {
    crate::logging::message(msg);
}

/// 构建登录用的 HTTP 客户端；`direct = true` 时额外禁用系统代理。
///
/// `cookie_store(true)` 是必须的：原脚本用同一个 `httpx.Client` 先 GET 认证页、
/// 再 POST 登录，登录请求依赖 GET 阶段网关下发的会话 Cookie。
///
/// **除 `direct` 那一个开关外，这里与 v2.0.0 逐字一致，不要再加别的字段。**
/// v2.0.1 加过 `.no_proxy()`、v2.0.2 加过 `.user_agent()` 与浏览器 Accept 头，
/// 都让原本能登录的版本变得完全登不上；v2.0.4 把这些全部回退后，2026-09-19 的日志
/// 仍与原样一字不差——可见问题不在这些字段上，但那也不构成「可以随手再加」的理由。
fn build_login_client(config: &Config, direct: bool) -> Result<Client, reqwest::Error> {
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

    let mut builder = Client::builder()
        .cookie_store(true)
        .default_headers(headers)
        .danger_accept_invalid_certs(config.danger_accept_invalid_certs);
    if direct {
        builder = builder.no_proxy();
    }
    builder.build()
}

/// 从 SSO 跳转中解析出的登录所需信息
struct RedirectInfo {
    /// 网关登录接口。
    login_url: String,
    /// 原始会话参数，作为 queryString 提交。
    query_string: String,
    /// 认证页面地址，作为 Referer 提交。
    referer: String,
}

/// 登录请求会把密码发往这个主机，因此只接受私有地址，避免被伪造成认证入口的
/// 外部主机骗走凭据。
fn is_private_host(host: &str) -> bool {
    host.parse::<std::net::Ipv4Addr>()
        .is_ok_and(|ip| ip.is_private())
}

/// reqwest 与自实现 HTTP 的认证响应正文。
struct Fetched {
    status: u16,
    body: Vec<u8>,
}

/// 与网关通信可以走的三条路。
///
/// 为什么要三条：2026-09-17 与 09-19 两次现场日志都显示，同一台机器、同一时刻、
/// 同一目标，亲手写的裸 HTTP 请求每次都拿得到网关的认证页（`HTTP/1.1 200 ok`，418 字节），
/// 而 reqwest 一律 `[请求] ← SendRequest ← connection closed before message completed`。
/// 这中间换过三套客户端配置（v2.0.1 加 `no_proxy()`、v2.0.2 加浏览器 UA 与 Accept、
/// v2.0.4 又全部回退），两次日志一字不差——原因不在客户端配置里。
///
/// 所以这里不再押注某一种解释：三条路按序试，用走得通的那条，并把用的是哪条写进日志。
#[derive(Clone, Copy, PartialEq, Eq)]
enum Path {
    /// reqwest，沿用 v2.0.0 的配置（会自动使用系统代理）
    Proxy,
    /// reqwest，但禁用系统代理
    Direct,
    /// 亲手写照字节的 HTTP/1.1，绕开 reqwest 与 hyper
    Raw,
}

impl Path {
    /// 日志里用的短名字。
    fn label(self) -> &'static str {
        match self {
            Path::Proxy => "reqwest+系统代理",
            Path::Direct => "reqwest+直连",
            Path::Raw => "自实现 HTTP",
        }
    }
}

/// 与网关通信的客户端集合，自带「哪条路能通」的记忆。
pub struct Gateway {
    /// 登录请求（GET 认证页、POST 登录）：要 Cookie 罐、跟随重定向
    login_proxy: Client,
    login_direct: Client,
    /// 绕开 reqwest 的那条路，自带 Cookie 罐
    raw: RawClient,
    /// 当前认为走得通的路
    path: Path,
}

impl Gateway {
    pub fn new(config: &Config) -> Result<Self, String> {
        Ok(Self {
            login_proxy: build_login_client(config, false)
                .map_err(|error| format!("无法创建 HTTP 客户端（系统代理）: {error}"))?,
            login_direct: build_login_client(config, true)
                .map_err(|error| format!("无法创建 HTTP 客户端（直连）: {error}"))?,
            raw: RawClient::new(),
            path: Path::Proxy,
        })
    }

    /// 三条路的尝试顺序：记住的那条排最前，其余按「直连优先于自实现」兜底。
    fn order(&self) -> [Path; 3] {
        match self.path {
            Path::Proxy => [Path::Proxy, Path::Direct, Path::Raw],
            Path::Direct => [Path::Direct, Path::Proxy, Path::Raw],
            Path::Raw => [Path::Raw, Path::Proxy, Path::Direct],
        }
    }

    /// 一条路走通后记住它。换了路一定要说一声：这句是排查时最要紧的一条日志。
    fn remember(&mut self, path: Path) {
        if path != self.path {
            show_msg(&format!("  改走「{}」这条路径", path.label()));
            self.path = path;
        }
    }

    /// 登录流程用的 GET：与 POST 共用同一个 Cookie 罐。
    fn get_login(&mut self, url: &str) -> Result<Fetched, LoginError> {
        let mut last = None;
        for candidate in self.order() {
            let outcome = match candidate {
                Path::Proxy => reqwest_fetch(&self.login_proxy, url, GET_TIMEOUT),
                Path::Direct => reqwest_fetch(&self.login_direct, url, GET_TIMEOUT),
                Path::Raw => self.raw.get(url),
            };
            match outcome {
                Ok(fetched) => {
                    self.remember(candidate);
                    return Ok(fetched);
                }
                Err(error) => {
                    show_msg(&format!("  {} 不通：{error}", candidate.label()));
                    last = Some(error);
                }
            }
        }
        Err(last.unwrap_or_else(|| LoginError::Unexpected("三条路径都走不通".to_string())))
    }

    /// POST 表单，同样是三条路按序试。
    fn post_form(&mut self, url: &str, referer: &str, body: &str) -> Result<Fetched, LoginError> {
        let mut last = None;
        for candidate in self.order() {
            let outcome = match candidate {
                Path::Proxy => reqwest_post(&self.login_proxy, url, referer, body),
                Path::Direct => reqwest_post(&self.login_direct, url, referer, body),
                Path::Raw => self.raw.post_form(url, referer, body),
            };
            match outcome {
                Ok(fetched) => {
                    self.remember(candidate);
                    return Ok(fetched);
                }
                Err(error) => {
                    show_msg(&format!("  {} 不通：{error}", candidate.label()));
                    last = Some(error);
                }
            }
        }
        Err(last.unwrap_or_else(|| LoginError::Unexpected("三条路径都走不通".to_string())))
    }
}

/// 用 reqwest 取一次，并压成统一形状。
fn reqwest_fetch(client: &Client, url: &str, timeout: Duration) -> Result<Fetched, LoginError> {
    let response = client
        .get(url)
        .timeout(timeout)
        .send()
        .map_err(LoginError::from_reqwest)?;
    Ok(fetched_from_reqwest(response))
}

/// 用 reqwest 发一次表单 POST。
fn reqwest_post(
    client: &Client,
    url: &str,
    referer: &str,
    body: &str,
) -> Result<Fetched, LoginError> {
    let referer = HeaderValue::from_str(referer)
        .map_err(|error| LoginError::Unexpected(format!("非法的 Referer 头: {error}")))?;
    let response = client
        .post(url)
        .header(REFERER, referer)
        .timeout(POST_TIMEOUT)
        .body(body.to_string())
        .send()
        .map_err(LoginError::from_reqwest)?;
    Ok(fetched_from_reqwest(response))
}

/// 把 reqwest 的响应压成统一形状。
fn fetched_from_reqwest(response: reqwest::blocking::Response) -> Fetched {
    let status = response.status().as_u16();
    let mut body = Vec::new();
    // 读超时或读失败也保留已经读到的部分，不影响后续判断
    let _ = response.take(MAX_BODY_BYTES).read_to_end(&mut body);
    Fetched { status, body }
}

/// 从地址里拆出主机、端口、请求目标，并解析出要连的地址。
fn split_target(url: &str) -> Result<(String, String, SocketAddr), String> {
    let parsed = Url::parse(url).map_err(|error| format!("地址无法解析（{error}）"))?;
    if parsed.scheme() != "http" {
        return Err("自实现 HTTP 路径仅支持 HTTP；HTTPS 认证请使用 reqwest 路径。".into());
    }
    let host = parsed.host_str().ok_or("地址里没有主机名")?.to_string();
    let port = parsed.port_or_known_default().unwrap_or(80);

    let mut target = parsed.path().to_string();
    if target.is_empty() {
        target.push('/');
    }
    if let Some(query) = parsed.query() {
        target.push('?');
        target.push_str(query);
    }

    let mut addrs = (host.as_str(), port)
        .to_socket_addrs()
        .map_err(|error| format!("{host}:{port} 解析不出地址（{error}）"))?;
    let addr = addrs
        .next()
        .ok_or_else(|| format!("{host}:{port} 没有可用地址"))?;
    let authority = match parsed.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    };
    Ok((authority, target, addr))
}

/// 裸连一次、把请求发出去、读到结束，返回原始字节。
///
/// 保留系统错误原文：连不上或发不出去时，它是唯一能说明原因的线索。
fn raw_exchange(addr: &SocketAddr, request: &str, timeout: Duration) -> Result<Vec<u8>, String> {
    let mut stream = TcpStream::connect_timeout(addr, timeout)
        .map_err(|error| format!("{addr} 连不上（{error}）"))?;
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));
    stream
        .write_all(request.as_bytes())
        .map_err(|error| format!("请求发不出去（{error}）"))?;

    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => {
                buffer.extend_from_slice(&chunk[..read]);
                if buffer.len() >= MAX_RAW_BYTES {
                    break;
                }
            }
            // 读超时也保留已经读到的部分
            Err(error) => {
                if buffer.is_empty() {
                    return Err(format!("读响应失败（{error}）"));
                }
                break;
            }
        }
    }
    Ok(buffer)
}

/// 裸请求拿回来的响应。
struct RawResponse {
    status: u16,
    /// 头名统一转成小写，便于按名字取
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl RawResponse {
    #[cfg(test)]
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }
}

/// 解析一段完整的 HTTP/1.1 响应。
///
/// 只按 `Connection: close` 的用法来：正文由 `Content-Length` 或分块编码界定，
/// 两者都没有就读到连接关闭为止。
fn parse_raw_response(bytes: &[u8]) -> Result<RawResponse, String> {
    let split = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| format!("响应头没收全（只拿到 {} 字节）", bytes.len()))?;

    let head = String::from_utf8_lossy(&bytes[..split]);
    let mut lines = head.lines();
    let status_line = lines.next().unwrap_or_default();
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| format!("状态行读不出状态码：{status_line}"))?;

    let mut headers = Vec::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
        }
    }

    let chunked = headers.iter().any(|(name, value)| {
        name == "transfer-encoding" && value.to_ascii_lowercase().contains("chunked")
    });
    let length = headers
        .iter()
        .find(|(name, _)| name == "content-length")
        .and_then(|(_, value)| value.trim().parse::<usize>().ok());

    let mut body = bytes[split + 4..].to_vec();
    if chunked {
        body = decode_chunked(&body);
    } else if let Some(length) = length {
        body.truncate(length.min(body.len()));
    }
    Ok(RawResponse {
        status,
        headers,
        body,
    })
}

/// 解开分块编码。网关若用 chunked 回登录结果，不解就会把块头当成 JSON 的一部分。
fn decode_chunked(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut rest = body;
    while let Some(end) = rest.windows(2).position(|window| window == b"\r\n") {
        // 块大小后面可能跟 `;扩展`，只取前面那一段
        let size_text = String::from_utf8_lossy(&rest[..end]);
        let size =
            usize::from_str_radix(size_text.split(';').next().unwrap_or_default().trim(), 16)
                .unwrap_or(0);
        if size == 0 {
            break;
        }
        let start = end + 2;
        if start + size > rest.len() {
            out.extend_from_slice(&rest[start..]);
            break;
        }
        out.extend_from_slice(&rest[start..start + size]);
        rest = &rest[start + size..];
        // 跳过块尾的 CRLF
        if rest.starts_with(b"\r\n") {
            rest = &rest[2..];
        }
    }
    out
}

/// 亲手写照字节的 HTTP 客户端，完全绕开 reqwest 与 hyper。
///
/// 自带一个极简 Cookie 罐：网关下发的会话 Cookie 要原样带给登录请求。
struct RawClient {
    /// 形如 `名字=值`
    cookies: Vec<String>,
}

impl RawClient {
    fn new() -> Self {
        Self {
            cookies: Vec::new(),
        }
    }

    fn get(&mut self, url: &str) -> Result<Fetched, LoginError> {
        self.send("GET", url, &[], None).map(Fetched::from)
    }

    fn post_form(&mut self, url: &str, referer: &str, body: &str) -> Result<Fetched, LoginError> {
        let headers = [
            (
                "Content-Type",
                "application/x-www-form-urlencoded; charset=UTF-8",
            ),
            ("Referer", referer),
        ];
        self.send("POST", url, &headers, Some(body))
            .map(Fetched::from)
    }

    /// 发一次请求。
    ///
    /// 头名按大写写（`Host`、`User-Agent`）：这是实测拿得到网关响应的写法，别改成小写。
    fn send(
        &mut self,
        method: &str,
        url: &str,
        headers: &[(&str, &str)],
        body: Option<&str>,
    ) -> Result<RawResponse, LoginError> {
        let (host, target, addr) = split_target(url).map_err(LoginError::Unexpected)?;

        let mut request = format!(
            "{method} {target} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {USER_AGENT}\r\nAccept: */*\r\n"
        );
        for (name, value) in headers {
            request.push_str(&format!("{name}: {value}\r\n"));
        }
        if !self.cookies.is_empty() {
            request.push_str(&format!("Cookie: {}\r\n", self.cookies.join("; ")));
        }
        if let Some(body) = body {
            request.push_str(&format!("Content-Length: {}\r\n", body.len()));
        }
        // 一次一连接：不碰连接复用，也就没有「复用了已关闭的连接」这种故障
        request.push_str("Connection: close\r\n\r\n");
        if let Some(body) = body {
            request.push_str(body);
        }

        let bytes = raw_exchange(&addr, &request, RAW_TIMEOUT).map_err(LoginError::Unexpected)?;
        let response = parse_raw_response(&bytes).map_err(LoginError::Unexpected)?;
        self.remember_cookies(&response);
        Ok(response)
    }

    /// 收下响应里的会话 Cookie，只留 `名字=值`，属性丢掉。
    fn remember_cookies(&mut self, response: &RawResponse) {
        for (name, value) in &response.headers {
            if name != "set-cookie" {
                continue;
            }
            let pair = value.split(';').next().unwrap_or_default().trim();
            if pair.is_empty() {
                continue;
            }
            let key = pair.split('=').next().unwrap_or_default();
            self.cookies
                .retain(|existing| !existing.starts_with(&format!("{key}=")));
            self.cookies.push(pair.to_string());
        }
    }
}

impl From<RawResponse> for Fetched {
    fn from(response: RawResponse) -> Self {
        Self {
            status: response.status,
            body: response.body,
        }
    }
}

/// 把 `reqwest::Error` 展开成摘要加完整原因链。
///
/// `reqwest::Error` 的 `Display` 只给一行摘要（`error sending request for url (...)`），
/// 真正的原因（连接被重置、DNS 失败、协议错误、系统错误码）全在 `source()` 链里。
/// 只打摘要就分不清是网络层不通还是 HTTP 层被拒，只能反复猜——所以这条链必须打出来。
fn describe(error: &reqwest::Error) -> String {
    let mut text = error.to_string();

    let mut kinds = Vec::new();
    if error.is_timeout() {
        kinds.push("超时");
    }
    if error.is_connect() {
        kinds.push("连接");
    }
    if error.is_request() {
        kinds.push("请求");
    }
    if error.is_body() {
        kinds.push("正文");
    }
    if error.is_decode() {
        kinds.push("解码");
    }
    if error.is_redirect() {
        kinds.push("跳转");
    }
    if error.is_status() {
        kinds.push("状态码");
    }
    if error.is_builder() {
        kinds.push("构建");
    }
    if !kinds.is_empty() {
        text.push_str(&format!(" [{}]", kinds.join("+")));
    }

    let mut cause = error.source();
    while let Some(error) = cause {
        text.push_str(&format!(" ← {error}"));
        cause = error.source();
    }
    text
}

/// 校验手动输入的地址；不会发出网络请求或回显个人参数。
pub fn validate_auth_url(entry: &str) -> Result<(), LoginError> {
    service_url_from_entry(entry).map(|_| ())
}

/// SSO 地址先解码 service；门户地址直接使用原始会话参数。
fn service_url_from_entry(entry: &str) -> Result<String, LoginError> {
    let entry = entry.trim();
    if entry.is_empty() {
        return Err(LoginError::Flow(
            "请填写认证 URL：复制浏览器地址栏中的完整校园网认证地址。".into(),
        ));
    }
    let parse = |value: &str| -> Result<Url, LoginError> {
        let parsed = Url::parse(value).map_err(|_| {
            LoginError::Flow("认证 URL 格式错误，请复制完整的 http:// 或 https:// 地址。".into())
        })?;
        if !matches!(parsed.scheme(), "http" | "https")
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.fragment().is_some()
            || value.chars().any(char::is_whitespace)
        {
            return Err(LoginError::Flow(
                "认证 URL 必须是完整的 HTTP / HTTPS 地址，不能包含空白、用户名或片段。".into(),
            ));
        }
        Ok(parsed)
    };
    let parsed = parse(entry)?;
    let portal = if parsed.host_str() == Some(SSO_HOST) && parsed.path() == "/login" {
        parsed
            .query_pairs()
            .find(|(key, _)| key == "service")
            .map(|(_, value)| value.into_owned())
            .ok_or_else(|| {
                LoginError::Flow("SSO 认证 URL 缺少 service 参数，请重新复制完整地址。".into())
            })?
    } else {
        entry.to_owned()
    };
    let parsed_portal = parse(&portal)?;
    if !parsed_portal.host_str().is_some_and(is_private_host) {
        return Err(LoginError::Flow(
            "认证 URL 中的网关必须是校园网内网 IP 地址。".into(),
        ));
    }
    if parsed_portal.path() != "/eportal/index.jsp"
        || !parsed_portal
            .query_pairs()
            .any(|(key, value)| key == "wlanuserip" && !value.is_empty())
    {
        return Err(LoginError::Flow(
            "认证 URL 缺少有效的门户路径或 wlanuserip 会话参数，请重新复制完整认证地址。".into(),
        ));
    }
    Ok(portal)
}

/// 从用户指定的地址解析请求目标，保留原始 queryString、协议和端口。
fn redirect_info_from_entry(entry: &str) -> Result<RedirectInfo, LoginError> {
    let portal = service_url_from_entry(entry)?;
    let mut target =
        Url::parse(&portal).map_err(|_| LoginError::Flow("无法解析认证 URL。".into()))?;
    let query_string = target.query().unwrap_or_default().to_owned();
    target.set_path("/eportal/InterFace.do");
    target.set_query(Some("method=login"));
    Ok(RedirectInfo {
        login_url: target.to_string(),
        query_string,
        referer: portal,
    })
}

/// 先 GET 指定认证页取得 Cookie，再 POST 登录。
fn get_redirect_info(gateway: &mut Gateway, entry: &str) -> Result<RedirectInfo, LoginError> {
    let info = redirect_info_from_entry(entry)?;
    show_msg("正在使用手动填写的认证 URL 解析服务器信息...");
    if let Err(error) = gateway.get_login(&info.referer) {
        show_msg(&format!("  认证页没取到（{error}），仍继续尝试登录"));
    }
    Ok(info)
}

/// 尝试登录一次。对应原脚本的 `login_attempt`。
///
/// 与 Python 版本一样，本函数把"业务失败"（索引越界、登录被拒、响应非 JSON）
/// 视作正常返回 `Ok(())`，只有真正需要提示用户的异常才走 `Err`。
pub fn login_attempt(gateway: &mut Gateway, config: &Config) -> Result<(), LoginError> {
    if config.service_index == 0 || config.service_index > SERVICE_COUNT {
        show_msg(&format!("服务索引必须在 1 到 {SERVICE_COUNT} 之间"));
        return Ok(());
    }

    let info = get_redirect_info(gateway, &config.auth_url)?;

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

    let fetched = gateway.post_form(&info.login_url, &info.referer, &body)?;
    if !(200..300).contains(&fetched.status) {
        show_msg(&format!(
            "登录接口返回 HTTP {}，请检查认证 URL 是否仍有效。",
            fetched.status
        ));
    }

    // 先拿到响应正文再解析网关 JSON；原始响应不写入日志，避免泄露认证信息。
    let text = String::from_utf8_lossy(&fetched.body);

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
        // 请求地址带有个人会话参数，不放入日志或错误链。
        let error = error.without_url();
        if error.is_timeout() || error.is_connect() {
            LoginError::Network(error)
        } else {
            LoginError::Unexpected(describe(&error))
        }
    }
}

impl fmt::Display for LoginError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoginError::Flow(message) => write!(f, "{message}"),
            LoginError::Network(error) => {
                write!(
                    f,
                    "网络连接错误：可能未联网或服务器无响应。({})",
                    describe(error)
                )
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
    fn manual_sso_and_portal_urls_keep_identical_session_parameters() {
        let portal = "http://10.245.2.20/eportal/index.jsp?wlanuserip=SECRET&mac=a%2Bb&t=wireless-v2&url=x%252Fy";
        let mut sso = Url::parse("https://sso.yzu.edu.cn/login").unwrap();
        sso.query_pairs_mut().append_pair("service", portal);
        for entry in [portal.to_owned(), sso.to_string(), format!("  {portal}  ")] {
            let info = redirect_info_from_entry(&entry).unwrap();
            assert_eq!(
                info.login_url,
                "http://10.245.2.20/eportal/InterFace.do?method=login"
            );
            assert_eq!(
                info.query_string,
                "wlanuserip=SECRET&mac=a%2Bb&t=wireless-v2&url=x%252Fy"
            );
            assert_eq!(info.referer, portal);
        }
    }

    #[test]
    fn manual_url_preserves_scheme_and_port() {
        let info =
            redirect_info_from_entry("https://10.245.2.20:8443/eportal/index.jsp?wlanuserip=test")
                .unwrap();
        assert_eq!(
            info.login_url,
            "https://10.245.2.20:8443/eportal/InterFace.do?method=login"
        );
    }

    #[test]
    fn rejects_incomplete_or_unsafe_manual_urls_without_echoing_parameters() {
        for entry in [
            "", "not a URL", "https://sso.yzu.edu.cn/login",
            "http://10.245.2.20/eportal/index.jsp", "http://10.245.2.20/eportal/index.jsp?wlanuserip=",
            "http://10.245.2.20/eportal/redirectortosuccess.jsp?wlanuserip=SECRET",
            "http://evil.example/eportal/index.jsp?wlanuserip=SECRET",
            "https://sso.yzu.edu.cn/login?service=http%3A%2F%2Fevil.example%2Feportal%2Findex.jsp%3Fwlanuserip%3DSECRET",
            "ftp://10.245.2.20/eportal/index.jsp?wlanuserip=SECRET",
            "http://user:SECRET@10.245.2.20/eportal/index.jsp?wlanuserip=test",
            "http://10.245.2.20/eportal/index.jsp?wlanuserip=SECRET#fragment",
            "http://10.245.2.20/eportal/index.jsp?wlanuserip=SECRET mac=x",
        ] {
            let error = validate_auth_url(entry).unwrap_err().to_string();
            assert!(!error.contains("SECRET"));
        }
    }

    #[test]
    fn manual_login_requests_only_configured_portal_and_reuses_cookies() {
        use std::net::TcpListener;
        use std::thread;
        use std::time::Instant;

        // A local proxy records every request without contacting the campus gateway.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let server = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(15);
            let mut requests = Vec::new();
            for index in 0..4 {
                let mut stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(Instant::now() < deadline, "missing portal request");
                            thread::sleep(Duration::from_millis(10));
                        }
                        Err(error) => panic!("{error}"),
                    }
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut bytes = Vec::new();
                loop {
                    let mut chunk = [0; 4096];
                    let count = stream.read(&mut chunk).unwrap();
                    assert!(count > 0, "incomplete request");
                    bytes.extend_from_slice(&chunk[..count]);
                    if let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
                        let headers = String::from_utf8_lossy(&bytes[..end]).to_ascii_lowercase();
                        let length = headers
                            .lines()
                            .find_map(|line| line.strip_prefix("content-length:"))
                            .map(|length| length.trim().parse::<usize>().unwrap())
                            .unwrap_or(0);
                        if bytes.len() >= end + 4 + length {
                            break;
                        }
                    }
                }
                requests.push(String::from_utf8(bytes).unwrap());
                let body = if index % 2 == 0 {
                    "portal"
                } else {
                    r#"{"result":"success"}"#
                };
                write!(stream, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nSet-Cookie: JSESSIONID=test-session; Path=/\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            }
            requests
        });
        let portal =
            "http://10.245.2.20/eportal/index.jsp?wlanuserip=SESSION&mac=a%2Bb&t=wireless-v2";
        let mut sso = Url::parse("https://sso.yzu.edu.cn/login").unwrap();
        sso.query_pairs_mut().append_pair("service", portal);
        let mut config: Config =
            toml::from_str("user_id = 'test-user'\npassword = 'test-password'\nservice_index = 2")
                .unwrap();
        let mut gateway = Gateway::new(&config).unwrap();
        gateway.login_proxy = Client::builder()
            .proxy(reqwest::Proxy::all(format!("http://{proxy_address}")).unwrap())
            .cookie_store(true)
            .build()
            .unwrap();
        for entry in [portal.to_owned(), sso.to_string()] {
            config.auth_url = entry;
            config.validate().unwrap();
            login_attempt(&mut gateway, &config).unwrap();
        }
        let requests = server.join().unwrap();
        for pair in requests.as_chunks::<2>().0 {
            assert!(pair[0].starts_with(&format!("GET {portal} HTTP/1.1\r\n")));
            assert!(pair[1].starts_with(
                "POST http://10.245.2.20/eportal/InterFace.do?method=login HTTP/1.1\r\n"
            ));
            let (headers, body) = pair[1].split_once("\r\n\r\n").unwrap();
            assert!(headers
                .to_ascii_lowercase()
                .contains("cookie: jsessionid=test-session"));
            assert!(headers.contains(portal));
            let form: std::collections::HashMap<_, _> =
                url::form_urlencoded::parse(body.as_bytes())
                    .into_owned()
                    .collect();
            assert_eq!(
                form["queryString"],
                "wlanuserip=SESSION&mac=a%2Bb&t=wireless-v2"
            );
            assert_eq!(form["userId"], "test-user");
            assert_eq!(form["password"], "test-password");
            assert_eq!(form["service"], SERVICE_LIST[1]);
        }
    }

    #[test]
    fn network_errors_hide_url_session_parameters() {
        // Binding without accepting prevents port reuse while the request times out.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let target = format!(
            "http://{}/eportal/index.jsp?wlanuserip=SECRET&mac=SECRETMAC",
            listener.local_addr().unwrap()
        );
        let error = Client::builder()
            .no_proxy()
            .build()
            .unwrap()
            .get(target)
            .timeout(Duration::from_millis(100))
            .send()
            .unwrap_err();
        let message = LoginError::from_reqwest(error).to_string();
        assert!(!message.contains("SECRET"));
    }

    #[test]
    fn raw_fallback_does_not_send_plaintext_for_https() {
        assert!(split_target("https://10.245.2.20/eportal/index.jsp?wlanuserip=test").is_err());
    }

    #[test]
    fn parses_raw_response_and_clips_to_content_length() {
        // 网关声明了长度：正文必须按声明截断，多出来的字节（这里故意多塞）要丢掉
        let raw = b"HTTP/1.1 200 ok\r\nServer: x\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhelloEXTRA";
        let response = parse_raw_response(raw).expect("应能解析");
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"hello");
        assert_eq!(response.header("server"), Some("x"));
        // 头名统一小写，方便按名字取
        assert!(response.header("Server").is_none());
    }

    #[test]
    fn decodes_chunked_raw_response() {
        let raw = b"HTTP/1.1 200 ok\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let response = parse_raw_response(raw).expect("应能解析");
        assert_eq!(response.body, b"hello world");
    }

    #[test]
    fn rejects_incomplete_raw_response() {
        // 头没收全时必须报错，而不是拿半截当成功
        assert!(parse_raw_response(b"HTTP/1.1 200 ok\r\nServer: x\r\n").is_err());
        assert!(parse_raw_response(b"").is_err());
    }

    #[test]
    fn keeps_only_the_cookie_pair() {
        let mut client = RawClient::new();
        let raw = b"HTTP/1.1 200 ok\r\nSet-Cookie: JSESSIONID=abc; Path=/; HttpOnly\r\nContent-Length: 0\r\n\r\n";
        let response = parse_raw_response(raw).expect("应能解析");
        client.remember_cookies(&response);
        assert_eq!(client.cookies, vec!["JSESSIONID=abc".to_string()]);
        // 同名 Cookie 要被覆盖，不能攒成两条
        client.remember_cookies(&response);
        assert_eq!(client.cookies.len(), 1);
    }
}
