# 钥盾 KeyShield · 校园 AI 密钥安全管理平台

> 服务端版 v3.3 · 面向个人、班级/科研团队、学校/企业的密钥托管、安全代理与本地化交付

钥盾把学校采购或团队共用的 AI API Key 留在服务器中：成员获得使用权，浏览器只收到模型回答，不收到真实 Key；每次调用都能追溯到具体用户、团队、资源、模型和请求号。

## 现在能演示什么

- 个人空间：独立加密保险箱、打码、查看、轮换、到期信息和个人审计。
- 团队空间：班级管控与科研协作两种模式、入队审核、成员有效期、团队密钥和成员用量统计。
- 学校/企业空间：全局托管、用户启停、管理员授权、邮箱验证注册和全站审计。
- 校园订阅交付：进入学校/企业空间前可选择“安装包本地部署”或“协助部署”，订阅生效后安全下载安装包。
- 真实代理：支持 DeepSeek、OpenAI、通义千问、Kimi、智谱清言、硅基流动的 OpenAI 兼容接口。
- 成员专属虚拟 Key：成员为自己签发 `ks_live_...`，可直接接入支持 OpenAI 协议的 IDE/脚本；真厂商 Key 不下发，虚拟 Key 明文也不入库。
- 邮箱认证：注册必须验证邮箱，登录支持用户名/邮箱 + 密码；找回密码需要邮箱验证码与一次性保险箱恢复密钥，敏感管理员授权可启用邮箱二次验证。
- 防篡改审计：每条日志通过 HMAC-SHA256 前后相连，并用数据库外 `.audit_anchor` 锚定总数和链头；删除、改写或截断日志都会使校验失败并阻止继续追加。
- 成本保护：每用户每分钟限流、每日调用上限、单次最大输出 Token；生产环境默认禁止直接下发真 Key。

## 本地运行（Windows）

```powershell
cd "KeyShield-v1"
.\.venv\Scripts\python.exe app.py
```

打开 `http://127.0.0.1:8800`。本地默认是演示模式，可在注册页直接获得演示验证码；公网生产模式不会显示或发送演示验证码。

本地环境同时开启演示订阅，学校/企业购买页中的“演示开通订阅”只用于验证业务流程，不会产生费用。正式部署默认关闭该按钮，订阅、报价与协助部署请联系 [1287585727@qq.com](mailto:1287585727@qq.com)。

### 校园部署购买与安装包

- 安装包本地部署：学校自行准备服务器并维护，订阅后下载安装包、自动部署脚本与安全说明。
- 协助部署：由服务方协助完成服务器环境、域名、HTTPS、管理员初始化和上线验证，订阅后同样提供安装包留档。
- 下载接口会再次校验登录状态和有效订阅；安装包采用固定文件白名单生成，不包含 `keyshield.db`、`.site_key`、`.flask_secret`、用户 API Key 或 `.venv`。
- 当前项目未接入第三方支付网关；生产环境通过联系邮箱确认报价、合同与订阅状态，避免页面虚构支付成功。

首次创建管理员必须在本机终端或服务器 SSH 中执行：

```powershell
.\.venv\Scripts\python.exe admin_setup.py
```

公网注册永远创建普通用户。后续管理员只能由现有管理员在“用户管理”中重新验证密码后授权。若误删全部管理员，可在本机/SSH 执行零管理员恢复（有管理员存在时命令会拒绝）：

```powershell
.\.venv\Scripts\python.exe admin_setup.py --promote-existing "用户名"
```

## 自动检查

启动本地服务后运行完整业务回归：

```powershell
.\.venv\Scripts\python.exe self_check.py
```

无需启动服务即可运行隔离的生产安全检查（使用临时数据库，不碰现有数据）：

```powershell
.\.venv\Scripts\python.exe production_check.py
```

当前验证基线：业务回归 64/64，通过；生产安全检查 29/29，通过。生产检查包含邮箱验证码不回显、恢复密钥明文不入库、敏感操作二次验证、安全 Cookie/HSTS 协议匹配、虚拟 Key 撤销即时失效，以及真实改写日志后的篡改检出测试。

历史开发环境曾保存第三方自动化扫描报告，本评审源码仓库不附带这些历史报告。本次隔离验证结果见 [VALIDATION.md](VALIDATION.md)。

## Ubuntu/Debian 公网部署

1. 准备域名并把 A/AAAA 记录指向服务器。
2. 将完整项目上传到 `/opt/keyshield`，不要覆盖或删除已有 `/var/lib/keyshield` 数据目录。
3. 只在云安全组开放 TCP 80/443，不开放 8800。
4. 执行：

```bash
cd /opt/keyshield
sudo KEYSHIELD_DOMAIN=keys.example.edu.cn \
     KEYSHIELD_EMAIL=ops@example.edu.cn \
     bash deploy/deploy.sh
```

脚本会创建低权限 `keyshield` 用户、独立虚拟环境、systemd 服务、Nginx 反向代理、Let's Encrypt HTTPS、每日备份定时器，并运行健康检查。应用只监听 `127.0.0.1:8800`。

部署后：

```bash
systemctl status keyshield
journalctl -u keyshield -n 100 --no-pager
curl https://keys.example.edu.cn/api/health
sudo keyshield-backup
```

如果没有同时提供域名和邮箱，脚本只会得到 HTTP 地址并打印警告；该状态只适合临时内网检查，不应承载真实密钥。

### 生产环境开关

部署脚本写入 `/etc/keyshield/keyshield.env`：

| 变量 | 生产默认值 | 作用 |
|---|---:|---|
| `KEYSHIELD_ENV` | `production` | 启用安全 Cookie、HSTS 等生产策略 |
| `KEYSHIELD_DEMO_MODE` | `0` | 关闭演示验证码、演示调用和演示数据注入 |
| `KEYSHIELD_REQUIRE_INVITE` | `0` | 是否额外要求管理员一次性邀请码；默认仅需邮箱验证码 |
| `KEYSHIELD_ALLOW_DIRECT` | `0` | 禁止浏览器查看托管真 Key |
| `KEYSHIELD_DEMO_BILLING` | `0` | 关闭不产生费用的演示订阅开通入口 |
| `KEYSHIELD_COOKIE_SECURE` | HTTPS 部署为 `1`，纯 HTTP 路演为 `0` | 控制登录 Cookie 是否只允许通过 HTTPS 发送；正式使用必须为 `1` |
| `KEYSHIELD_EMAIL_MODE` | `smtp` | 正式邮件通道；本地演示模式使用 `demo` 并回显虚构验证码 |
| `KEYSHIELD_EMAIL_STEP_UP` | `1` | 已绑定邮箱的管理员执行角色授权时要求邮箱二次验证 |
| `KEYSHIELD_SMTP_HOST` | 未设置 | SMTP 服务器地址；未配置时生产环境拒绝伪装发送成功 |
| `KEYSHIELD_SMTP_PORT` | `465` | SMTP 端口 |
| `KEYSHIELD_SMTP_USER` | 未设置 | SMTP 登录账号 |
| `KEYSHIELD_SMTP_PASSWORD` | 未设置 | SMTP 授权码/密码，只写入服务器 0600 环境文件，不写进源码或日志 |
| `KEYSHIELD_SMTP_FROM` | 同 SMTP 账号 | 发件人地址 |
| `KEYSHIELD_SMTP_SSL` | `1` | 使用 SMTP over TLS；若使用 STARTTLS 则设为 `0` |
| `KEYSHIELD_SMTP_STARTTLS` | SSL 时为 `0` | 非 SSL 连接是否升级为 STARTTLS |
| `KEYSHIELD_DAILY_CALL_LIMIT` | `100` | 每名用户每天最多安全代理调用次数 |
| `KEYSHIELD_MAX_OUTPUT_TOKENS` | `1024` | 单次厂商请求的最大输出 Token |
| `KEYSHIELD_VIRTUAL_KEY_MAX_DAYS` | `90` | 成员虚拟 Key 最长有效天数 |

QQ 邮箱可使用 `sudo bash /opt/keyshield/deploy/configure_qq_email.sh` 安全配置。脚本会在终端中提示输入完整 QQ 邮箱和 SMTP 授权码，授权码输入过程不可见，只写入权限为 0600 的服务器环境文件；不要使用 QQ 登录密码，也不要把授权码写进聊天、源码或工作日志。

## 密钥逻辑（通俗版）

个人保险箱像“每个人一只保险柜”：系统为每位用户随机生成一把数据钥匙（DEK），用它通过 AES-256-GCM 加密个人 API Key；用户密码只负责派生另一把包装钥匙（KEK），再把 DEK 锁起来。因此改密码只需换 DEK 外面的锁，不必重加密所有数据。

学校和团队托管区像“前台代刷门禁”：托管 Key 用服务器独有的 `.site_key` 加密。成员点击调用时，服务器才在内存中短暂解密，向固定白名单厂商发 HTTPS 请求，然后只把回答和用量返回浏览器。Key 不写入日志、不进入响应。

成员虚拟 Key 像“实名临时工牌”：每位成员拿到自己的 `ks_live_...`，数据库只保存用站点密钥 HMAC 后的摘要。每次调用都会重新确认账号、团队成员资格、资源领用、有效期和独立日额度，并把用量记到具体成员和具体虚拟 Key；团队资源被撤销、成员过期或虚拟 Key 被撤销后会立即失效。

兼容 OpenAI SDK 时，把页面显示的 Base URL 和只显示一次的虚拟 Key 填入客户端即可；当前版本支持非流式文本对话：

```python
from openai import OpenAI

client = OpenAI(api_key="ks_live_仅显示一次", base_url="https://你的域名/v1")
answer = client.chat.completions.create(
    model="auto",
    messages=[{"role": "user", "content": "你好"}],
)
```

浏览器 Cookie 只保存随机会话编号。解包后的个人 DEK 仅在单个服务进程内存中保存，30 分钟无操作失效；服务器重启后所有人需要重新登录。

### 邮箱验证与保险箱恢复

邮箱验证码只证明“当前操作者能接收该邮箱的邮件”，不能代替密码解开个人 DEK。新用户注册或旧用户绑定邮箱时，系统会生成一把高熵 `KS-REC-...` 恢复密钥，只显示一次；数据库只保存由该恢复密钥派生的 KEK 对用户 DEK 的第二份 AES-256-GCM 包装，不保存恢复密钥明文。

忘记密码时必须同时提供邮箱验证码和恢复密钥。验证通过后，服务器才能在本次请求内解出用户 DEK，并立即使用新密码派生的 KEK 重新包装；缺少恢复密钥时，邮箱或管理员都无法绕过密码保护读取个人保险箱。团队/学校托管资源仍遵循站点密钥与代理调用机制。

正式部署需在 `/etc/keyshield/keyshield.env` 中配置 SMTP 参数并执行 `sudo systemctl restart keyshield`。建议使用专用发信账号或事务邮件服务，不要把授权码提交到项目文件、聊天记录或工作日志。

## 备份与恢复边界

- `/var/lib/keyshield/keyshield.db`：账号、密文、团队、授权、审计和用量。
- `/var/lib/keyshield/.site_key`：解密学校/团队托管 Key 的根密钥。
- `/var/lib/keyshield/.flask_secret`：保持会话签名一致；丢失不会破坏密文，但会使现有登录全部失效。
- `/var/lib/keyshield/.audit_anchor`：数据库外的审计链总数、链头和 HMAC 签名；用于发现数据库内日志被删除或截断。

数据库、`.site_key` 和 `.audit_anchor` 必须成套异地备份；缺少 `.site_key` 时托管 Key 无法恢复，缺少匹配的 `.audit_anchor` 时无法证明审计链未被截断。`deploy/backup.sh` 会生成权限为 0600 的成套压缩包并保留 14 天。

## 目录

```text
app.py                  Flask API、权限、加密、厂商代理与数据库迁移
admin_setup.py          SSH/本机首个管理员初始化
templates/index.html    响应式官网与三类业务后台
self_check.py           端到端业务回归（自动清理测试数据）
production_check.py     临时目录中的生产安全回归
requirements.txt        生产依赖版本范围
deploy/deploy.sh        Nginx + HTTPS + systemd 生产部署
deploy/backup.sh        SQLite 与站点密钥一致性备份
docs/VALIDATION.md      本次发布的隔离验证结果
DEVLOG.md               按日期记录的开发工作日志
```

## 当前工程边界

本版本适合单台云服务器上的路演、试点和小规模真实使用。SQLite、内存会话和本地限流按“单进程、单实例”设计；若要做多机高可用，需要把会话、限流和数据库迁移到共享基础设施，并增加正式的监控告警与灾备演练。
