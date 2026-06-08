from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent
APP_DIR = ROOT / "app"
ENV_FILE = ROOT / ".env"

BACKEND_MODULES = ["uvicorn", "fastapi", "sqlalchemy", "pydantic_settings"]
BOT_MODULES = ["aiogram"]


def parse_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip("\"'")
    return values


def backend_python() -> Path | str:
    if os.name == "nt":
        candidate = ROOT / ".venv" / "Scripts" / "python.exe"
    else:
        candidate = ROOT / ".venv" / "bin" / "python"
    return candidate if candidate.exists() else sys.executable


def missing_modules(python: Path | str, modules: list[str]) -> list[str] | None:
    if not modules:
        return []
    code = (
        "import importlib.util, sys; "
        "missing = [m for m in sys.argv[1:] if importlib.util.find_spec(m) is None]; "
        "print('\\n'.join(missing)); "
        "raise SystemExit(1 if missing else 0)"
    )
    result = subprocess.run(
        [str(python), "-c", code, *modules],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    if result.returncode == 0:
        return []
    if result.returncode == 1:
        return [line.strip() for line in result.stdout.splitlines() if line.strip()]
    print(f"[error] Could not run backend Python: {python}")
    print(result.stdout, end="")
    return None


def check_python_dependencies(python: Path | str, *, need_backend: bool, need_bot: bool) -> bool:
    modules: list[str] = []
    if need_backend:
        modules.extend(BACKEND_MODULES)
    if need_bot:
        modules.extend(BOT_MODULES)
    missing = missing_modules(python, modules)
    if missing is None:
        return False
    if not missing:
        return True
    print(f"[error] Missing Python modules for {python}: {', '.join(missing)}")
    print("[error] Install backend dependencies with:")
    print(f"[error]   {python} -m pip install -r {ROOT / 'requirements.txt'}")
    return False


def print_checks(env: dict[str, str], *, strict_https: bool) -> None:
    base_url = public_base_url(env)
    token = env.get("TELEGRAM_BOT_TOKEN", "")

    if not ENV_FILE.exists():
        print(f"[check] Missing {ENV_FILE}. Copy .env.example to .env first.")
    if not token:
        print("[check] TELEGRAM_BOT_TOKEN is empty. Telegram bot will not start correctly.")
    if strict_https and not base_url.startswith("https://"):
        print("[check] Telegram Web Apps require DOMAIN to resolve to an HTTPS URL.")
        print(f"[check] Current public URL: {base_url or '<empty>'}")
        print("[check] Use a public HTTPS domain, or pass --allow-http for local testing.")


def public_base_url(env: dict[str, str]) -> str:
    domain = env.get("DOMAIN", "")
    domain = domain.strip().rstrip("/")
    if not domain:
        return ""
    if domain.startswith(("http://", "https://")):
        return domain
    return f"https://{domain}"


def backend_bind(env: dict[str, str], host: str | None, port: int | None) -> tuple[str, int]:
    bind_host = host or env.get("HOST", "127.0.0.1")
    bind_port = port
    if bind_port is None:
        try:
            bind_port = int(env.get("PORT", "8000"))
        except ValueError:
            print("[check] PORT is invalid. Falling back to 8000.")
            bind_port = 8000
    return bind_host, bind_port


def stream_output(name: str, process: subprocess.Popen[str]) -> None:
    assert process.stdout is not None
    for line in process.stdout:
        print(f"[{name}] {line}", end="")


def start_process(name: str, args: list[str | Path]) -> subprocess.Popen[str]:
    creationflags = 0
    if os.name == "nt":
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP

    process = subprocess.Popen(
        [str(arg) for arg in args],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        creationflags=creationflags,
    )
    threading.Thread(target=stream_output, args=(name, process), daemon=True).start()
    print(f"[start] {name} started with pid {process.pid}")
    return process


def stop_process(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return

    try:
        if os.name == "nt":
            process.send_signal(signal.CTRL_BREAK_EVENT)
        else:
            process.terminate()
        process.wait(timeout=8)
    except Exception:
        process.kill()


def main() -> int:
    parser = argparse.ArgumentParser(description="Start dn42 Autopeer backend and Telegram bot.")
    parser.add_argument(
        "--allow-http",
        action="store_true",
        help=(
            "Start even when DOMAIN does not resolve to HTTPS. "
            "Telegram Web App verification will not work."
        ),
    )
    parser.add_argument(
        "--backend-only",
        action="store_true",
        help="Start only the FastAPI backend.",
    )
    parser.add_argument(
        "--bot-only",
        action="store_true",
        help="Start only the Telegram bot.",
    )
    parser.add_argument(
        "--host",
        help="Backend listen host. Defaults to HOST or 127.0.0.1.",
    )
    parser.add_argument(
        "--port",
        type=int,
        help="Backend listen port. Defaults to PORT or 8000.",
    )
    args = parser.parse_args()

    if args.backend_only and args.bot_only:
        print("[error] Choose at most one of --backend-only or --bot-only.")
        return 2

    if args.allow_http:
        # Local testing mode: also tolerate placeholder SESSION_SECRET / TELEGRAM_BACKEND_SECRET
        # so the backend does not refuse to start. Never use --allow-http in production.
        os.environ["ALLOW_INSECURE_DEFAULTS"] = "1"

    if not APP_DIR.exists():
        print(f"[error] App package not found: {APP_DIR}")
        return 1

    env = parse_env(ENV_FILE)
    print_checks(env, strict_https=not args.allow_http)

    if not args.allow_http and not public_base_url(env).startswith("https://"):
        print("[error] Refusing to start because Telegram verification needs HTTPS.")
        print("[error] Pass --allow-http for local backend-only testing.")
        return 1

    python = backend_python()
    if not check_python_dependencies(
        python, need_backend=not args.bot_only, need_bot=not args.backend_only
    ):
        return 1

    bind_host, bind_port = backend_bind(env, args.host, args.port)
    processes: list[subprocess.Popen[str]] = []

    try:
        if not args.bot_only:
            processes.append(
                start_process(
                    "backend",
                    [
                        python,
                        "-m",
                        "uvicorn",
                        "app.main:app",
                        "--host",
                        bind_host,
                        "--port",
                        str(bind_port),
                        "--reload",
                    ],
                )
            )
        if not args.backend_only:
            processes.append(start_process("bot", [python, "-m", "app.bot.main"]))

        while processes:
            for process in processes:
                exit_code = process.poll()
                if exit_code is not None:
                    print(f"[stop] Process pid {process.pid} exited with code {exit_code}")
                    return exit_code
            threading.Event().wait(0.5)
    except KeyboardInterrupt:
        print("\n[stop] Ctrl+C received, stopping services...")
    finally:
        for process in processes:
            stop_process(process)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
