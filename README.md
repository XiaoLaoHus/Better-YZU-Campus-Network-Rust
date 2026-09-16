## Better-YZU-Campus-Network-扬州大学校园网自动登录脚本（Rust 版）

* 这是一个用于实现扬州大学校园网自动登录和断线重连的脚本。脚本通过解析 SSO 入口 URL 中的易通网关参数，模拟 POST 请求完成认证。
* 本项目是原 [Python 单文件脚本](../) 的 Rust 重写版，使用 GitHub Actions 编译，可产出免运行时的单文件可执行程序。
* 欢迎各位批评指导
* 晚安！


-----

### 1\. 功能概述

  * **自动登录：** 无需手动操作，自动完成校园网认证。
  * **断线重连：** 每隔 10 分钟（`interval_secs`，默认 600 秒）自动检查并尝试重新连接，确保网络持续在线。
  * **参数内置：** 网关参数解析逻辑已内置，用户无需手动复制复杂的认证 URL。
  * **单文件发行：** 编译产物是单个可执行文件，无需 Python 环境，也不用先装解释器和依赖。

### 2\. 环境要求

#### 方式一：下载编译好的可执行文件（推荐）

前往本仓库的 [Actions](../../actions) 页面，打开最近一次成功的 workflow 运行，
在页面底部的 **Artifacts** 区域下载对应平台的可执行文件，解压后即可运行。

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

```bash
# 使用当前目录下的 config.toml
./better-yzu-campus-network

# 指定配置文件路径
./better-yzu-campus-network --config /path/to/config.toml

# 只尝试登录一次后退出（调试用）
./better-yzu-campus-network --once

# 查看帮助
./better-yzu-campus-network --help
```

#### 后台常驻

Linux / macOS：

```bash
nohup ./better-yzu-campus-network > yzu.log 2>&1 &
```

Windows（开机自启可在“任务计划程序”里添加触发器）：

```powershell
Start-Process -WindowStyle Hidden .\better-yzu-campus-network.exe
```

-----

### 4\. 项目结构

```
Cargo.toml               依赖与构建配置
config.example.toml      配置模板（提交到仓库）
config.toml              你的真实配置（不提交）
src/
  main.rs                入口：读取配置、主循环、参数解析
  config.rs              Config 结构体、加载与校验
  login.rs               网关参数解析与登录请求
.github/workflows/ci.yml 编译、检查与冒烟测试
```

-----

### 5\. 故障排除

  * **`无法读取配置文件 config.toml`：** 还没有创建配置文件。复制 `config.example.toml` 为 `config.toml` 并填写。
  * **登录失败：** 请检查 `config.toml` 里填的 **`user_id`** 和 **`password`** 是否准确无误。
  * **`网络连接错误：可能未联网或服务器无响应。`：** 当前设备不在校园网内，或网关不可达。
  * **服务器响应格式错误：** 脚本在断网或半连接状态下可能无法获得标准的 JSON 响应。脚本已添加错误处理，会自动重试。
  * **其他错误：** 可以带着截图联系我，虽然我可能也解决不了

-----

### 6\. 从 Python 版迁移的差异

  * 账号密码从源码硬编码改为 `config.toml` 配置文件。
  * 新增 `--once` / `--config` / `--help` 命令行参数（Python 版是直接改源码里的常量）。
  * 原脚本行尾的"喵"依然保留。

> **注意：** 如果你之前在源码里硬编码过账号密码，请注意那些凭据可能已经留在 git 历史中。
> 改代码不会清除历史，建议同时修改密码，必要时使用 `git filter-repo` 清理。
