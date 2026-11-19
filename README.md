# 钥盾 KeyShield（第一版）

校园 AI 密钥安全管理平台，面向评审提供可在本地复现的 Demo 源码。
本仓库发布原版服务端（内部版本 v3.3），不包含后续 KeyShield-Agent 扩展版。

## 环境与安装

需要 Python 3.10 或以上版本，首次安装依赖需要联网。下载本仓库 ZIP 并解压，或使用 Git 克隆，然后在源码目录打开终端。

Windows PowerShell：

```powershell
$env:PYTHONPATH=""
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-lock.txt
.\.venv\Scripts\python.exe app.py
```

macOS / Linux：

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-lock.txt
PYTHONPATH= .venv/bin/python app.py
```

访问 **http://127.0.0.1:8800**。应用首次启动自动生成本地数据库和密钥文件，无需下载预置数据库。默认仅监听本机。停止服务按 Ctrl+C。

## 评审演示步骤

1. **注册与登录**：注册页填写演示邮箱，点击获取验证码。本地默认演示模式会回显验证码，无需 SMTP；完成注册后妥善保存一次性保险箱恢复密钥。
2. **个人保险箱**：登录后载入演示数据，查看打码、查看密钥、轮换、分类及审计记录。内置数据均为虚构数据。
3. **管理员功能**：另开终端运行 `.\.venv\Scripts\python.exe admin_setup.py`（macOS/Linux 使用 `.venv/bin/python admin_setup.py`），按提示创建首位管理员。回到网页使用该管理员登录，查看用户管理和学校托管中心。
4. **团队协作**：分别注册两个账号，用两个浏览器会话演示创建团队、申请加入、审核、团队密钥与成员权限。
5. **托管与权限**：管理员新增演示托管密钥，成员领用后执行不带提示词的演示调用，检查审计与用量，再撤销授权验证失效。可使用虚构值 `sk-demo-keyshield-1234567890`，分类选择 DeepSeek。
6. **订阅交付**：学校/企业页面选择部署方案，点击演示开通订阅并下载源码安装包，不会产生费用。

**演示与真实代理的区别**：无提示词的演示调用验证授权和审计，不请求真实模型。输入提示词会走真实厂商接口，需要自备有效 API Key、网络和额度，可能产生厂商费用。虚构密钥不能生成真实模型回答。演示邮箱验证码和演示订阅仅用于本地演示。

## 一条命令验证

无需事先启动服务；脚本在临时目录复制源码、创建数据库、启动随机本地端口并自动清理，不接触正常使用的数据：

```powershell
.\.venv\Scripts\python.exe verify_demo.py
```

macOS/Linux 使用 `.venv/bin/python verify_demo.py`。包括完整业务回归与生产策略隔离检查；失败时返回非零退出码。

验证覆盖注册/找回密码、个人密钥、团队、学校托管、虚拟 Key、撤销、权限校验、订阅包与审计链篡改检测。真实第三方模型调用、真实发信和公网 HTTPS 部署需另行配置与验证。

## 结构与部署

| 文件 | 用途 |
|---|---|
| `app.py`、`templates/index.html` | Flask 服务端与网页界面 |
| `admin_setup.py` | 本机初始化管理员 |
| `requirements-lock.txt` | 本次验证使用的完整依赖版本 |
| `requirements.txt` | 允许的直接依赖版本范围 |
| `verify_demo.py` | 一键隔离验证 |
| `self_check.py`、`production_check.py` | 业务回归与生产安全检查 |
| `deploy/` | Ubuntu/Debian 部署、备份与 SMTP 配置脚本 |
| [部署与架构说明](docs/DEPLOYMENT.md) | 加密机制、配置和生产部署细节 |

不要提交数据库、`.site_key`、`.flask_secret`、`.audit_anchor`、备份、SMTP 密码或真实 API Key。生产部署必须关闭演示模式并配置 HTTPS、邮件与备份。

项目按单进程、单实例设计，SQLite、内存会话和限流适合演示及小规模试点。源码仓库链接是可复现交付入口，不代表已提供公网在线服务。
