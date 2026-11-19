"""在临时副本中验证演示，避免修改使用者的数据库。"""
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request


def main():
    source = Path(__file__).resolve().parent
    with tempfile.TemporaryDirectory(prefix="keyshield-demo-check-") as directory:
        target = Path(directory)
        for name in ("app.py", "admin_setup.py", "requirements.txt", "README.md",
                     "self_check.py", "production_check.py"):
            shutil.copy2(source / name, target / name)
        for name in ("templates", "deploy"):
            shutil.copytree(source / name, target / name)
        env = {k: v for k, v in os.environ.items() if not k.startswith("KEYSHIELD_")}
        env.update(PYTHONPATH="", PYTHONIOENCODING="utf-8", KEYSHIELD_ENV="development",
                   KEYSHIELD_DEMO_MODE="1", KEYSHIELD_EMAIL_MODE="demo",
                   KEYSHIELD_DEMO_BILLING="1", KEYSHIELD_DATA_DIR=directory,
                   NO_PROXY="127.0.0.1,localhost", no_proxy="127.0.0.1,localhost")
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        env["KEYSHIELD_BASE_URL"] = f"http://127.0.0.1:{port}"
        with (target / "server.log").open("w", encoding="utf-8") as log:
            server = subprocess.Popen([sys.executable, "-c",
                f"from app import app; app.run(host='127.0.0.1', port={port}, debug=False)"],
                cwd=target, env=env, stdout=log, stderr=log)
            try:
                for _ in range(100):
                    if server.poll() is not None:
                        print((target / "server.log").read_text(encoding="utf-8", errors="replace"))
                        raise RuntimeError("演示服务启动失败")
                    try:
                        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(
                                env["KEYSHIELD_BASE_URL"] + "/api/health", timeout=1) as response:
                            if response.status == 200:
                                break
                    except OSError:
                        time.sleep(0.1)
                else:
                    raise RuntimeError("演示服务启动超时")
                subprocess.run([sys.executable, "self_check.py"], cwd=target, env=env, check=True)
            finally:
                server.terminate()
                server.wait(timeout=15)
        subprocess.run([sys.executable, "production_check.py"], cwd=target, env=env, check=True)


if __name__ == "__main__":
    main()
