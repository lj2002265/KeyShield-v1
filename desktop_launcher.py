"""第一版桌面交付入口：本机演示、按用户安装、隔离验证。"""
import argparse
import json
import os
from pathlib import Path
import runpy
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
import webbrowser

VERSION = '1.0.1'
ROOT = Path(__file__).resolve().parent
FROZEN = bool(getattr(sys, 'frozen', False))


def child_args(*args):
    return [sys.executable, *([] if FROZEN else [str(Path(__file__).resolve())]), *args]


def demo_environment(directory):
    # 桌面交付仅用于本机演示，不继承宿主生产环境或 SMTP 配置。
    for key in list(os.environ):
        if key.startswith('KEYSHIELD_'):
            del os.environ[key]
    os.environ.update(KEYSHIELD_ENV='development', KEYSHIELD_DEMO_MODE='1',
        KEYSHIELD_EMAIL_MODE='demo', KEYSHIELD_DEMO_BILLING='1',
        KEYSHIELD_ALLOW_DIRECT='0', KEYSHIELD_DATA_DIR=str(directory),
        PYTHONPATH='', PYTHONIOENCODING='utf-8')
    directory.mkdir(parents=True, exist_ok=True)


def install(args):
    if not FROZEN or os.name != 'nt':
        raise RuntimeError('安装入口仅适用于打包后的 Windows 程序。源码请使用 start-demo.cmd。')
    target = Path(args.target) if args.target else Path(os.environ['LOCALAPPDATA'])/'Programs'/'KeyShield-v1'
    target = target.resolve()
    target.mkdir(parents=True, exist_ok=True)
    destination = target/'KeyShield.exe'
    if Path(sys.executable).resolve() != destination:
        staged = target/'KeyShield.exe.new'
        shutil.copy2(sys.executable, staged)
        os.replace(staged, destination)
    if (ROOT/'THIRD-PARTY-LICENSES').is_dir():
        shutil.copytree(ROOT/'THIRD-PARTY-LICENSES',target/'THIRD-PARTY-LICENSES',dirs_exist_ok=True)
    if not args.no_shortcuts:
        env=os.environ.copy();env['KEYSHIELD_INSTALL_TARGET']=str(destination)
        env['KEYSHIELD_SHORTCUT_DIR']=str(Path(args.shortcut_dir).resolve()) if args.shortcut_dir else ''
        script=r'''
$ErrorActionPreference='Stop'
$exe=$env:KEYSHIELD_INSTALL_TARGET
$shell=New-Object -ComObject WScript.Shell
$desktop=[Environment]::GetFolderPath('Desktop')
$menu=Join-Path ([Environment]::GetFolderPath('Programs')) 'KeyShield'
if($env:KEYSHIELD_SHORTCUT_DIR){ $desktop=$env:KEYSHIELD_SHORTCUT_DIR; $menu=$desktop }
New-Item -ItemType Directory -Force -Path $menu | Out-Null
foreach($item in @(@($desktop,'KeyShield Demo.lnk','--serve'),@($menu,'KeyShield Demo.lnk','--serve'),@($menu,'KeyShield Admin.lnk','--admin'),@($menu,'KeyShield Verify.lnk','--verify'))){
  $link=$shell.CreateShortcut((Join-Path $item[0] $item[1]))
  $link.TargetPath=$exe
  $link.Arguments=$item[2]
  $link.WorkingDirectory=Split-Path $exe
  $link.Save()
}
'''
        subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',script],env=env,check=True)
    print(f'安装完成：{destination}\n程序版本：{VERSION}')
    if not args.no_shortcuts:print('启动快捷方式：KeyShield Demo')
    print('无需管理员权限；双击桌面入口后访问 http://127.0.0.1:8800 。')
    print('首次使用请注册账号；管理员请从开始菜单运行 KeyShield Admin。')
    if not args.no_pause:
        input('按回车关闭安装窗口。')


def verify():
    with tempfile.TemporaryDirectory(prefix='keyshield-desktop-check-') as directory:
        with socket.socket() as sock:
            sock.bind(('127.0.0.1',0)); port=sock.getsockname()[1]
        with open(Path(directory)/'server.log','w',encoding='utf-8') as log:
            server=subprocess.Popen(child_args('--serve','--no-browser','--port',str(port),'--data-dir',directory),stdout=log,stderr=log)
            try:
                opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
                for _ in range(300):
                    if server.poll() is not None:
                        raise RuntimeError(Path(directory,'server.log').read_text(encoding='utf-8',errors='replace'))
                    try:
                        with opener.open(f'http://127.0.0.1:{port}/api/health',timeout=1) as response:
                            if response.status==200:break
                    except OSError:time.sleep(.1)
                else:raise RuntimeError('临时服务启动超时')
                subprocess.run(child_args('--business-check','--data-dir',directory,'--port',str(port)),check=True)
            finally:
                server.terminate();server.wait(timeout=20)
        subprocess.run(child_args('--production-check'),check=True)
    print('桌面包验证完成：业务回归和生产策略检查均通过。')


def main():
    parser=argparse.ArgumentParser(description='钥盾第一版桌面演示与安装程序')
    parser.add_argument('--version',action='version',version='KeyShield '+VERSION)
    modes=parser.add_mutually_exclusive_group()
    for mode in ['install','serve','admin','verify','business-check','production-check']:
        modes.add_argument('--'+mode,action='store_true')
    parser.add_argument('--target')
    parser.add_argument('--no-shortcuts',action='store_true')
    parser.add_argument('--shortcut-dir',help='指定快捷方式目录，默认使用桌面及开始菜单')
    parser.add_argument('--no-pause',action='store_true')
    parser.add_argument('--no-browser',action='store_true')
    parser.add_argument('--data-dir')
    parser.add_argument('--port',type=int,default=8800)
    args=parser.parse_args()
    if args.install or (FROZEN and 'setup' in Path(sys.executable).stem.lower() and len(sys.argv)==1):
        return install(args)
    if args.verify:return verify()
    if args.production_check:
        # 此脚本自行创建临时目录并启用生产开关。
        sys.argv=['production_check.py']
        return runpy.run_path(str(ROOT/'production_check.py'),run_name='__main__')
    data=Path(args.data_dir).resolve() if args.data_dir else Path(os.environ.get('LOCALAPPDATA',str(Path.home())))/'KeyShield-v1'/'demo-data'
    demo_environment(data)
    if args.business_check:
        os.environ['KEYSHIELD_BASE_URL']=f'http://127.0.0.1:{args.port}'
        os.environ['NO_PROXY']=os.environ['no_proxy']='127.0.0.1,localhost'
        sys.argv=['self_check.py']
        return runpy.run_path(str(ROOT/'self_check.py'),run_name='__main__')
    if args.admin:
        sys.argv=['admin_setup.py']
        return runpy.run_path(str(ROOT/'admin_setup.py'),run_name='__main__')
    # 启动失败时不打开可能属于其他程序的网页。
    from waitress import create_server
    from app import app
    server=create_server(app,host='127.0.0.1',port=args.port,threads=4)
    url=f'http://127.0.0.1:{args.port}'
    print(f'钥盾 {VERSION} 本机演示已启动：{url}\n数据目录：{data}',flush=True)
    print('本地演示验证码直接显示。真实模型请求需自行提供有效密钥。\n请保持窗口开启，按 Ctrl+C 停止。',flush=True)
    if not args.no_browser:webbrowser.open(url)
    try:server.run()
    except KeyboardInterrupt:pass
    finally:server.close()


if __name__=='__main__':
    try:main()
    except Exception as exc:
        print(f'操作失败：{exc}',file=sys.stderr)
        if FROZEN and sys.stdin.isatty() and '--no-pause' not in sys.argv:
            input('请查看上述原因，按回车关闭。')
        raise SystemExit(1)
