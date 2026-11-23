# 钥盾第一版安装说明

交付版本：v1.0.1。业务基线：v1.0.0 原版服务端。Windows 包包含 Python 和运行依赖，无需单独安装 Python，不需要管理员权限。

## 下载和安装

1. 打开 [v1.0.1 发布页](https://github.com/lj2002265/KeyShield-v1/releases/tag/v1.0.1)。
2. 下载 `KeyShield-Setup-v1.0.1-windows-x64.exe`，适用于 Windows 10/11 的 x64 电脑。
3. 双击安装程序。控制台显示安装结果，程序写入 `%LOCALAPPDATA%\Programs\KeyShield-v1\KeyShield.exe`。
4. 按回车关闭安装窗口，双击桌面的 `KeyShield Demo` 快捷方式。
5. 浏览器自动打开 `http://127.0.0.1:8800`。若没有自动打开，可手动输入该地址。保持服务窗口开启，按 Ctrl+C 停止。

安装程序只创建当前用户的程序文件和快捷方式，不注册系统服务、不添加开机启动、不打开防火墙端口。重复安装会替换程序，不删除独立的数据目录；升级前应先关闭正在运行的钥盾窗口。

安装包尚未购买代码签名证书。如果系统安全策略不允许运行未签名程序，可使用源码 Demo；不要关闭防病毒或系统安全保护。可对照发布页 `SHA256SUMS.txt` 校验下载文件：

```powershell
Get-FileHash .\KeyShield-Setup-v1.0.1-windows-x64.exe -Algorithm SHA256
```

## 数据、账号与管理员

桌面程序将数据库和密钥材料保存在 `%LOCALAPPDATA%\KeyShield-v1\demo-data`。应用第一次启动时自动创建，不附带现成账号。注册页使用本地演示验证码；注册后应保存一次性恢复密钥。

首位管理员通过开始菜单 `KeyShield > KeyShield Admin` 初始化，按提示输入用户名、手机号和至少 10 位密码。也可在终端运行以下命令：

```powershell
& "$env:LOCALAPPDATA\Programs\KeyShield-v1\KeyShield.exe" --admin
```

演示时可使用符合格式的虚构手机号，但请记住自己设置的账号与密码。已有管理员时初始化会拒绝重复创建。注册页始终创建普通用户，不提供固定默认管理员密码。

备份前停止程序，将整个 `demo-data` 目录复制到受保护的位置。数据库、`.site_key`、`.flask_secret`、`.audit_anchor` 需要成套保存；不要只复制数据库或把备份传到公开仓库。重新安装不会自动恢复丢失的密钥文件。

## 便携运行与检查

下载 `KeyShield-Demo-v1.0.1-windows-x64.zip` 并解压，双击 `Start-Demo.cmd` 即可运行，无需执行安装步骤。便携包与安装版默认使用同一用户数据目录，不要同时启动两个实例。

开始菜单 `KeyShield Verify` 可执行独立验证；便携包中双击 `Verify-Demo.cmd`，或执行 `KeyShield.exe --verify`。验证会建立临时数据、临时端口，并验证业务与生产策略，不修改现有账号数据。

## 常见问题与卸载

- 端口 8800 被占用：先确认是否已经开启钥盾。需要第二个独立实例时使用 `KeyShield.exe --serve --port 8810 --data-dir "D:\KeyShieldDemo2"`。
- 关闭窗口后网页不可用：本地服务已停止，重新启动桌面入口。
- 输入问题后模型报错：真实请求需要有效厂商密钥；虚构密钥只用于无提示词演示。
- 注册收不到邮件：桌面交付固定使用本地演示模式，验证码在页面回显，不发送真实邮件。
- 更新时文件占用：停止服务、退出初始化或验证窗口，再运行安装程序。
- 卸载：停止服务，删除安装目录和桌面、开始菜单中的钥盾快捷方式。默认保留 `demo-data`；只有确定不再需要数据并完成备份后才手动删除该目录。本版不登记 Windows“已安装的应用”。

## Linux、macOS 与公网部署

下载源码 Demo，Windows 执行 `start-demo.cmd`；Linux/macOS 执行 `bash start-demo.sh`。源码方式需要 Python 3.10+，首次安装依赖需要联网。Linux/macOS 启动脚本本次未实机验证。

Windows 安装版定位为本机演示工具，强制使用演示模式、仅监听 127.0.0.1、禁止托管密钥直接下发。公网部署请使用源码中的 `deploy/` 和 [部署说明](DEPLOYMENT.md)，自行配置 HTTPS、SMTP、备份及生产开关，不要将桌面演示服务直接映射到公网。
