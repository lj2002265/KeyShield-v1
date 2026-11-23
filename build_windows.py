"""Windows 构建入口：先安装 requirements-lock.txt 与 requirements-build.txt。"""
from pathlib import Path
import subprocess, sys, shutil
from importlib.metadata import distribution
root=Path(__file__).resolve().parent
licenses=root/'build'/'license-notices'
licenses.mkdir(parents=True,exist_ok=True)
packages=['Flask','cryptography','waitress','Werkzeug','Jinja2','MarkupSafe',
          'itsdangerous','click','blinker','cffi','pycparser','typing-extensions','pyinstaller']
for name in packages:
    dist=distribution(name)
    for f in dist.files or []:
        if any(word in str(f).lower() for word in ('license','copying','notice')):
            src=Path(dist.locate_file(f))
            if src.is_file():
                target=licenses/name/Path(str(f)).name
                target.parent.mkdir(parents=True,exist_ok=True)
                shutil.copy2(src,target)
python_license=Path(sys.base_prefix)/'LICENSE.txt'
if python_license.is_file():shutil.copy2(python_license,licenses/'Python-LICENSE.txt')
args=[sys.executable,'-m','PyInstaller','--noconfirm','--clean','--onefile','--console',
      '--name','KeyShield','--paths',str(root),'--hidden-import','app',
      '--hidden-import','waitress','--collect-all','cryptography']
args += ['--add-data',str(licenses)+':THIRD-PARTY-LICENSES']
for name in ['app.py','admin_setup.py','self_check.py','production_check.py','README.md',
             'requirements.txt','requirements-lock.txt','templates','deploy']:
    args += ['--add-data',str(root/name)+':.'] if '/' not in name and (root/name).is_file() else ['--add-data',str(root/name)+':'+name]
subprocess.run(args+[str(root/'desktop_launcher.py')],cwd=root,check=True)
