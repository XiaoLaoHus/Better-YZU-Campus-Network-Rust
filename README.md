## Better-YZU-Campus-Network-扬州大学校园网自动登录脚本（Rust 版）

* 这是一个用于实现扬州大学校园网自动登录和断线重连的脚本。脚本通过解析 SSO 入口 URL 中的易通网关参数，模拟 POST 请求完成认证。
* 本项目是原 [Python 单文件脚本](../) 的 Rust 重写版，使用 GitHub Actions 编译，可产出免运行时的单文件可执行程序。
* 欢迎各位批评指导
* 晚安！


-----

### 1\. 功能概述

  * **自动登录：** 无需手动操作，自动完成校园网认证。
  * **断线重连：** 每隔 10 分钟（`interval_secs`，默认 600 秒）自动检查并尝试重新连接，确保网络持续在线。
  * **参数自动获取：** 启动时先探测网关，现取本次连接的会话参数，用户无需手动复制复杂的认证 URL。程序访问一个外网地址，未认证时网关会把它拦下、换成认证页返回，会话参数就在认证页的地址里——这正是浏览器弹窗拿到的那份内容。参数按设备与当次连接生成，因此不会硬编码在程序里。
  * **Windows 图形窗口与托盘：** 双击启动，无控制台黑框；关闭或最小化窗口后仍在后台运行，点击托盘图标即可恢复。右键托盘可打开窗口或退出。
  * **运行日志：** Windows 窗口显示最近 200 行日志；登录请求在独立线程执行，界面不会因等待网络而卡住。
  * **单文件发行：** 编译产物是单个可执行文件，无需 Python 环境，也不用先装解释器和依赖。

### 2\. 环境要求

#### 方式一：下载编译好的可执行文件（推荐）

前往 [Releases](../../releases) 页面，下载对应平台的压缩包，解压后即可运行，
无需安装任何运行时环境。

| 平台 | 压缩包 |
| :--- | :--- |
| Windows | `...-windows-x86_64.zip` |
| Linux | `...-linux-x86_64.zip` |
| macOS（Apple Silicon） | `...-macos-arm64.zip` |
| macOS（Intel / 黑苹果） | `...-macos-x86_64.zip` |

> 每个包里包含可执行文件、`config.example.toml` 和本说明文档。

#### 方式二：自行编译

需要先安装 [Rust 工具链](https://rustup.rs)：

```bash
cargo build --release
```

产物位于 `target/release/better-yzu-campus-network`（Windows 下为 `.exe`）。

#### 配置信息修改（必需）

复制配置模板并填入你的真实信息：

```bash
cp config.example.toml config.toml
```

然后编辑 `config.toml`：

| 字段名 | 描述 |
| :--- | :--- |
| **`user_id`** | 您的学号或用户名。 |
| **`password`** | 您的校园网密码。 |
| **`service_index`** | 选择的网络服务，取值为 **1 到 5** 之间的整数。 |
| `interval_secs` | 可选，重连检查间隔（秒），默认 `600`。 |
| `danger_accept_invalid_certs` | 可选，是否跳过 TLS 证书校验，默认 `false`。 |

> **`service_index`** 对应服务：`1: 学校互联网, 2: 联通, 3: 移动, 4: 电信, 5: 校内免费`。

> `config.toml` 已被 `.gitignore` 忽略，账号密码不会进入版本库，也不会被编译进二进制文件。

-----

### 3\. 使用方法

#### Windows：窗口与系统托盘

1. 解压 Windows 发行包，在 **exe 所在目录**将 `config.example.toml` 复制为 `config.toml` 并填写账号信息。
2. 双击 `better-yzu-campus-network.exe`，窗口显示配置路径及登录日志，自动登录任务随即开始。
3. 点击 **隐藏到托盘**、窗口 **×** 或 **最小化**，窗口隐藏但后台任务不会停止。
4. 单击或双击通知区域的小图标恢复窗口；也可右键图标选择 **打开窗口**。图标可能在任务栏右下角的 **“显示隐藏的图标”** 中。
5. 需要真正结束程序时，点击窗口或托盘菜单中的 **退出**。退出会中断重连等待，在途网络请求结束后关闭程序，通常不超过 15 秒。

> 配置缺失/错误会自动显示窗口；修改配置后请退出并重新启动。托盘创建失败时窗口会保持可见，防止程序隐藏后无法恢复。资源管理器重启后会尝试恢复图标。
> 图形界面仅支持 Windows；Linux/macOS 保持命令行模式。请勿重复启动多个实例。

```powershell
# 启动后直接隐藏到托盘（可用于快捷方式或任务计划程序）
.\better-yzu-campus-network.exe --minimized

# 命令行模式：不创建图形窗口和托盘
.\better-yzu-campus-network.exe --console
```

#### 命令行与配置路径

Windows 图形模式默认读取 **程序所在目录**的 `config.toml`；`--console`、`--once` 和 Linux/macOS 默认读取 **当前工作目录**。显式 `--config` 优先，相对路径基于当前工作目录。

```bash
# Linux/macOS 命令行运行；Windows 不带参数则打开图形窗口
./better-yzu-campus-network

# 指定配置文件路径
./better-yzu-campus-network --config /path/to/config.toml

# 只尝试登录一次后退出，不创建窗口（调试用）
./better-yzu-campus-network --once

# 查看帮助
./better-yzu-campus-network --help
```

`--minimized` 仅支持 Windows，不能与 `--console` 或 `--once` 一起使用。Windows 程序采用 GUI 子系统；在脚本中需要等待其结束时，可使用 `Start-Process -Wait`。

#### 后台常驻

Linux / macOS：

```bash
nohup ./better-yzu-campus-network > yzu.log 2>&1 &
```

Windows 可在“任务计划程序”中配置启动程序与 `--minimized` 参数，选择 **仅当用户登录时运行**，以便显示托盘图标；无需再使用 `-WindowStyle Hidden`。

-----

### 4\. 项目结构

```
Cargo.toml                   依赖与构建配置
config.example.toml          配置模板（提交到仓库）
config.toml                  你的真实配置（不提交）
src/
  main.rs                    参数解析与 GUI / 命令行入口
  windows_ui.rs              Windows 窗口、托盘、隐藏/恢复/退出
  worker.rs                  后台登录循环与可中断等待
  logging.rs                 有界日志与敏感信息遮蔽
  config.rs                  Config 结构体、加载与校验
  login.rs                   网关参数解析与登录请求
.github/
  scripts/windows-smoke.py   Windows 窗口与命令行自动化冒烟
  workflows/ci.yml           三平台编译、单元测试、clippy 与冒烟测试
  workflows/release.yml      打 v* tag 时测试并构建四种架构发行包
```

-----

### 5\. 故障排除

  * **`无法读取配置文件 config.toml`：** 还没有创建配置文件。复制 `config.example.toml` 为 `config.toml` 并填写。
  * **登录失败：** 请检查 `config.toml` 里填的 **`user_id`** 和 **`password`** 是否准确无误。
  * **`网络连接错误：可能未联网或服务器无响应。`：** 当前设备不在校园网内，或网关不可达。
  * **`未能从网关取到认证入口，跳过本次登录。可能本机已在线；若确实断网，请保留上面的探测日志以便排查。`：** 探测的几个外网地址都没有被网关拦截（即没有拿到认证页），最常见的原因是本机已在线上，无需重复登录；想测试登录流程，需要先通过自助服务页面退出登录。若确实断网仍报这条，请把 `探测 <地址> ...` 那几行连同下方信息发来。**地址中的参数值不会写进日志**，可以放心贴出来。
  * **为什么不说「已在线」？** 实测这个网关在断网时也会把门户请求跳到 `redirectortosuccess.jsp`，据此判断「已在线」是误报，所以程序只做「拿到入口 / 没拿到」两种判断。
  * **服务器响应格式错误：** 脚本在断网或半连接状态下可能无法获得标准的 JSON 响应。脚本已添加错误处理，会自动重试。
  * **其他错误：** 可以带着截图联系我，虽然我可能也解决不了

-----

### 6\. 从 Python 版迁移的差异

  * 账号密码从源码硬编码改为 `config.toml` 配置文件。
  * 认证 URL 从源码硬编码改为运行时探测：Python 版内置了某一台设备的完整 SSO 入口 URL，其中的 IP、MAC 等参数只对那台设备有效；Rust 版改为每次登录前探测网关、从重定向地址或认证网页地址现取参数。
  * 新增 `--once` / `--config` / `--help` 命令行参数（Python 版是直接改源码里的常量）。
  * 原脚本行尾的"喵"依然保留。

> **注意：** 如果你之前在源码里硬编码过账号密码，请注意那些凭据可能已经留在 git 历史中。
> 改代码不会清除历史，建议同时修改密码，必要时使用 `git filter-repo` 清理。
