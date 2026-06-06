from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
import threading
from pathlib import Path


ROOT = Path(__file__).resolve().parent
BACKEND_DIR = ROOT / "backend"
ENV_FILE = BACKEND_DIR / ".env"


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
        candidate = BACKEND_DIR / ".venv" / "Scripts" / "python.exe"
    else:
        candidate = BACKEND_DIR / ".venv" / "bin" / "python"
    return candidate if candidate.exists() else sys.executable


def print_checks(env: dict[str, str], *, strict_https: bool) -> None:
    base_url = env.get("BASE_URL", "")
    token = env.get("TELEGRAM_BOT_TOKEN", "")

    if not ENV_FILE.exists():
        print(f"[check] Missing {ENV_FILE}. Copy backend/.env.example to backend/.env first.")
    if not token:
        print("[check] TELEGRAM_BOT_TOKEN is empty. Telegram bot will not start correctly.")
    if strict_https and not base_url.startswith("https://"):
        print("[check] Telegram Web Apps require BASE_URL to start with https://")
        print(f"[check] Current BASE_URL: {base_url or '<empty>'}")
        print("[check] Use a public HTTPS domain or a tunnel, then restart this script.")


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
        cwd=BACKEND_DIR,
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
        help="Start even when BASE_URL is not HTTPS. Telegram Web App verification will not work.",
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
    args = parser.parse_args()

    if args.backend_only and args.bot_only:
        print("[error] Choose at most one of --backend-only or --bot-only.")
        return 2

    if not BACKEND_DIR.exists():
        print(f"[error] Backend directory not found: {BACKEND_DIR}")
        return 1

    env = parse_env(ENV_FILE)
    print_checks(env, strict_https=not args.allow_http)

    if not args.allow_http and not env.get("BASE_URL", "").startswith("https://"):
        print("[error] Refusing to start because Telegram verification needs HTTPS.")
        print("[error] Pass --allow-http for local backend-only testing.")
        return 1

    python = backend_python()
    processes: list[subprocess.Popen[str]] = []

    try:
        if not args.bot_only:
            processes.append(start_process("backend", [python, "-m", "uvicorn", "app.main:app", "--reload"]))
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
