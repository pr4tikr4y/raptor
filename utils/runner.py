import subprocess
import shutil
import threading
from typing import Optional
from utils.logger import get_logger

log = get_logger()


def check_tool(name: str) -> bool:
    return shutil.which(name) is not None


def check_required_tools(tools: list) -> list:
    missing = [t for t in tools if not check_tool(t)]
    return missing


def run_command(
    cmd: list,
    timeout: int = 300,
    capture: bool = True,
    proxy: Optional[str] = None,
    env: Optional[dict] = None,
) -> tuple[int, str, str]:
    import os

    run_env = os.environ.copy()
    if env:
        run_env.update(env)
    if proxy:
        run_env["http_proxy"] = proxy
        run_env["https_proxy"] = proxy
        run_env["HTTP_PROXY"] = proxy
        run_env["HTTPS_PROXY"] = proxy

    log.debug(f"Running: {' '.join(str(c) for c in cmd)}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=capture,
            text=True,
            timeout=timeout,
            env=run_env,
        )
        return result.returncode, result.stdout or "", result.stderr or ""
    except subprocess.TimeoutExpired:
        log.warning(f"Command timed out after {timeout}s: {cmd[0]}")
        return -1, "", "timeout"
    except FileNotFoundError:
        log.error(f"Tool not found: {cmd[0]}")
        return -1, "", f"not found: {cmd[0]}"
    except Exception as e:
        log.error(f"Command failed: {e}")
        return -1, "", str(e)


def stream_command(cmd: list, on_line=None, timeout: int = 600, env: Optional[dict] = None):
    import os

    run_env = os.environ.copy()
    if env:
        run_env.update(env)

    log.debug(f"Streaming: {' '.join(str(c) for c in cmd)}")

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=run_env,
        )

        lines = []

        def read_stderr():
            for line in proc.stderr:
                line = line.strip()
                if line:
                    log.debug(f"[stderr] {line}")

        stderr_thread = threading.Thread(target=read_stderr, daemon=True)
        stderr_thread.start()

        for line in proc.stdout:
            line = line.strip()
            if line:
                lines.append(line)
                if on_line:
                    on_line(line)

        proc.wait(timeout=timeout)
        return proc.returncode, lines
    except subprocess.TimeoutExpired:
        proc.kill()
        log.warning(f"Stream command timed out: {cmd[0]}")
        return -1, []
    except Exception as e:
        log.error(f"Stream failed: {e}")
        return -1, []
