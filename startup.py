#!/usr/bin/env python3
"""米家 API 服务一键启动脚本（Python 版）
由 start_api_server.bat 调用，负责环境检测、依赖安装、动态调参和启动服务。
"""

import os
import sys
import time
import shutil
import subprocess
import tempfile
from pathlib import Path

# ── 全局变量（由 main 设置）───────────────────────────────
_root = None  # type: Path
_state_dir = None  # type: Path

# ── 配置常量 ──────────────────────────────────────────────
RETRY_COUNT = 3
RETRY_DELAY = 5  # 秒
MIN_FREE_RAM_MB = 1024
MIN_PROJECT_DISK_MB = 3072
MIN_STATE_DISK_MB = 2048
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = "8123"

# ── 输出辅助 ──────────────────────────────────────────────
STEP = 0


def step(title: str, detail: str = ""):
    global STEP
    STEP += 1
    print(f"\n[{STEP}/8] {title}")
    if detail:
        print(f"       {detail}")


def ok(msg: str):
    print(f"[通过] {msg}")


def info(msg: str):
    print(f"[提示] {msg}")


def warn(msg: str):
    print(f"[警告] {msg}")


def die(msg: str, impact: str = ""):
    print(f"[错误] {msg}")
    if impact:
        print(f"[影响] {impact}")
    sys.exit(1)


# ── 工具函数 ──────────────────────────────────────────────


def get_env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


def retry(action, desc: str) -> bool:
    for i in range(1, RETRY_COUNT + 1):
        info(f"{desc} 第 {i}/{RETRY_COUNT} 次...")
        try:
            action()
            return True
        except Exception:
            if i < RETRY_COUNT:
                warn(f"失败，{RETRY_DELAY} 秒后重试...")
                time.sleep(RETRY_DELAY)
    return False


def run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, **kwargs)


def run_check(cmd: list[str], **kwargs) -> bool:
    try:
        result = subprocess.run(cmd, capture_output=True, **kwargs)
        return result.returncode == 0
    except Exception:
        return False


def get_venv_python(venv_dir: Path) -> Path:
    if os.name == "nt":
        return venv_dir / "Scripts" / "python.exe"
    return venv_dir / "bin" / "python"


# ── 第 1 步：Python 已由 bat 找到，这里校验版本 ────────────


def check_python():
    info("当前 Python: " + sys.executable)
    info(f"版本: {sys.version}")
    if sys.version_info < (3, 9):
        die("Python 版本低于 3.9，需要 3.9 以上。", "服务不会启动。")
    ok("Python 版本符合要求。")


# ── 第 2 步：状态目录 ──────────────────────────────────────


def ensure_state_dir(root: Path) -> Path:
    preferred = os.environ.get("MIJIA_STATE_DIR", "")
    auto = not preferred
    if auto:
        preferred = str(Path.home() / "Documents" / "mijia-state")

    candidates = [preferred]
    if auto:
        local = str(Path(os.environ.get("LOCALAPPDATA", "")) / "mijia-state")
        temp = str(Path(tempfile.gettempdir()) / "mijia-state")
        if local != preferred:
            candidates.append(local)
        if temp != preferred and temp != local:
            candidates.append(temp)

    root_resolved = root.resolve()
    for cand in candidates:
        p = Path(cand)
        try:
            p.mkdir(parents=True, exist_ok=True)
            # 写测试
            test_file = p / ".write_test"
            test_file.write_text("test")
            test_file.unlink()
        except Exception:
            if cand == preferred:
                warn(f"默认状态目录不可写: {cand}，尝试其他位置...")
            continue

        # 不能在项目目录内
        try:
            resolved = p.resolve()
        except Exception:
            continue
        if resolved == root_resolved or str(resolved).startswith(
            str(root_resolved) + os.sep
        ):
            if cand == preferred:
                warn("状态目录不能位于项目目录内，已自动切换。")
            continue

        ok(f"状态目录可用: {resolved}")
        return resolved

    die("无法创建可用的状态目录。", "无法保存会话与缓存，服务不会启动。")


# ── 第 3 步：资源检测与自动调参 ────────────────────────────


def detect_resources() -> dict:
    cpu = os.cpu_count() or 2
    try:
        total_ram, free_ram = get_memory_mb()
    except Exception as e:
        warn(f"内存检测失败，已跳过内存限制: {e}")
        total_ram, free_ram = 0, 0
    proj_free = max(shutil.disk_usage(str(_root)).free // (1024 * 1024), 0)
    state_free = max(shutil.disk_usage(str(_state_dir)).free // (1024 * 1024), 0)

    info(f"CPU 核心: {cpu}")
    if total_ram > 0:
        info(f"总内存: {total_ram} MB，可用: {free_ram} MB")
    else:
        warn("未获取到内存信息，已忽略内存限制。")
    info(f"项目盘剩余: {proj_free} MB")
    info(f"状态盘剩余: {state_free} MB")

    if proj_free < MIN_PROJECT_DISK_MB:
        die(f"项目磁盘空间过低: {proj_free} MB，无法安装依赖。")
    if state_free < MIN_STATE_DISK_MB:
        die(f"状态磁盘空间过低: {state_free} MB，无法写入会话。")

    return {
        "cpu": cpu,
        "total_ram": total_ram,
        "free_ram": free_ram,
        "proj_free": proj_free,
        "state_free": state_free,
    }


def get_memory_mb() -> tuple[int, int]:
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.windll.kernel32

        class MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [
                ("dwLength", wintypes.DWORD),
                ("dwMemoryLoad", wintypes.DWORD),
                ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong),
                ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]

        mem = MEMORYSTATUSEX()
        mem.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
        kernel32.GlobalMemoryStatusEx(ctypes.byref(mem))
        return (
            int(mem.ullTotalPhys / (1024 * 1024)),
            int(mem.ullAvailPhys / (1024 * 1024)),
        )

    # Linux/macOS 优先用 sysconf，拿不到时再回退到 /proc/meminfo。
    try:
        page_size = os.sysconf("SC_PAGE_SIZE")
        total_pages = os.sysconf("SC_PHYS_PAGES")
        avail_pages = os.sysconf("SC_AVPHYS_PAGES")
        if page_size > 0 and total_pages > 0 and avail_pages >= 0:
            return (
                int(total_pages * page_size / (1024 * 1024)),
                int(avail_pages * page_size / (1024 * 1024)),
            )
    except (AttributeError, OSError, ValueError):
        pass

    meminfo = Path("/proc/meminfo")
    if meminfo.exists():
        values = {}
        for line in meminfo.read_text(encoding="utf-8", errors="ignore").splitlines():
            if ":" not in line:
                continue
            key, raw = line.split(":", 1)
            number = raw.strip().split()[0]
            if number.isdigit():
                values[key] = int(number)
        total_kb = values.get("MemTotal")
        free_kb = values.get("MemAvailable", values.get("MemFree"))
        if total_kb and free_kb is not None:
            return (total_kb // 1024, free_kb // 1024)

    raise RuntimeError("无法检测当前系统内存信息，请手动设置启动参数后重试。")


def tune_params(res: dict) -> dict:
    cpu = res["cpu"]
    free = res["free_ram"]
    memory_known = free > 0

    tp = min(max(cpu * 24, 64), 512)
    if memory_known:
        tp = min(tp, max(free // 16, 64))

    ml = min(max(cpu * 4, 8), 128)
    if memory_known and free < 2048:
        ml = min(ml, 16)

    mc = min(max(cpu * 120, 80), 1500)
    if memory_known:
        mc = min(mc, max(free // 8, 80))

    pr = min(max(mc // 2, 120), 600)
    rr = min(max(mc * 2, 240), 2400)
    wr = min(max(mc // 4, 60), 600)
    bk = min(max(mc * 40, 5000), 60000)
    rttl = 600

    # 环境变量覆盖
    tp = int(get_env("MIJIA_THREADPOOL_TOKENS", str(tp)))
    ml = int(get_env("MIJIA_MAX_ACTIVE_LOGIN_TASKS", str(ml)))
    mc = int(get_env("MIJIA_MAX_CONCURRENCY", str(mc)))
    pr = int(get_env("MIJIA_PUBLIC_RATE_LIMIT", str(pr)))
    rr = int(get_env("MIJIA_READ_RATE_LIMIT", str(rr)))
    wr = int(get_env("MIJIA_WRITE_RATE_LIMIT", str(wr)))
    bk = int(get_env("MIJIA_RATE_LIMIT_MAX_BUCKETS", str(bk)))
    rttl = int(get_env("MIJIA_RATE_BUCKET_TTL_SECONDS", str(rttl)))

    # 承载估算
    if memory_known:
        es = max(min(free // 24, cpu * 40, mc // 2), 30)
    else:
        es = max(min(cpu * 40, mc // 2), 30)
    eb = max(min(mc, es * 2), 60)

    host = get_env("MIJIA_WEB_HOST", DEFAULT_HOST)
    port = get_env("MIJIA_WEB_PORT", DEFAULT_PORT)

    return {
        "thread_pool": tp,
        "max_login": ml,
        "max_conc": mc,
        "public_rate": pr,
        "read_rate": rr,
        "write_rate": wr,
        "buckets": bk,
        "rate_ttl": rttl,
        "est_stable": es,
        "est_burst": eb,
        "host": host,
        "port": port,
    }


# ── 第 4 步：虚拟环境 ──────────────────────────────────────


def setup_venv(root: Path) -> Path:
    venv_dir = root / ".venv"
    venv_py = get_venv_python(venv_dir)

    if venv_py.exists():
        ok(f"已检测到虚拟环境: {venv_dir}")
        if run_check([str(venv_py), "-m", "pip", "--version"]):
            return venv_py
        info("venv 缺少 pip，正在修复...")
        if run_check([str(venv_py), "-m", "ensurepip", "--upgrade"]):
            if run_check([str(venv_py), "-m", "pip", "--version"]):
                ok("pip 已修复。")
                return venv_py
        warn("修复失败，正在重建 venv...")
        shutil.rmtree(venv_dir, ignore_errors=True)

    info("正在创建虚拟环境...")
    result = run([sys.executable, "-m", "venv", str(venv_dir)])
    if result.returncode != 0 or not venv_py.exists():
        die("创建虚拟环境失败。")

    run([str(venv_py), "-m", "ensurepip", "--upgrade"], capture_output=True)
    if not run_check([str(venv_py), "-m", "pip", "--version"]):
        die("pip 初始化失败。")

    ok("虚拟环境已创建。")
    return venv_py


# ── 第 5 步：升级 pip 工具 ─────────────────────────────────


def upgrade_pip_tools(venv_py: Path):
    def _upgrade():
        result = run(
            [
                str(venv_py),
                "-m",
                "pip",
                "install",
                "--upgrade",
                "pip",
                "setuptools",
                "wheel",
                "--disable-pip-version-check",
                "--timeout",
                "120",
            ],
            capture_output=True,
        )
        if result.returncode != 0:
            raise RuntimeError("pip upgrade failed")

    if retry(_upgrade, "升级 pip 工具"):
        ok("pip 基础工具已就绪。")
    else:
        warn("pip 基础工具升级失败，将继续使用当前环境。")


# ── 第 6 步：安装项目依赖 ─────────────────────────────────


def install_project(venv_py: Path, root: Path):
    def _install():
        result = run(
            [
                str(venv_py),
                "-m",
                "pip",
                "install",
                "-e",
                str(root),
                "--disable-pip-version-check",
                "--timeout",
                "120",
            ],
            capture_output=True,
            cwd=str(root),
        )
        if result.returncode != 0:
            raise RuntimeError(
                result.stderr.decode("utf-8", errors="replace")[-500:]
            )

    if retry(_install, "安装项目依赖"):
        ok("项目依赖安装完成。")
    else:
        die("项目依赖安装失败。", "服务不会启动，请根据上方报错处理后重试。")


# ── 第 7 步：输出摘要 ─────────────────────────────────────


def print_summary(res: dict, params: dict):
    print("=" * 60)
    print("  米家 API 服务 - 启动配置")
    print("=" * 60)
    print(f"  项目目录             : {_root}")
    print(f"  状态目录             : {_state_dir}")
    print(f"  监听地址             : {params['host']}")
    print(f"  监听端口             : {params['port']}")
    print(f"  访问地址             : http://{params['host']}:{params['port']}")
    print(f"  CPU 核心数           : {res['cpu']}")
    print(f"  总内存 / 可用 (MB)   : {res['total_ram']} / {res['free_ram']}")
    print(f"  项目盘剩余 (MB)      : {res['proj_free']}")
    print(f"  状态盘剩余 (MB)      : {res['state_free']}")
    print(f"  最大并发请求         : {params['max_conc']}")
    print(f"  线程池令牌           : {params['thread_pool']}")
    print(f"  最大登录并发         : {params['max_login']}")
    print(
        f"  公共接口限流         : {params['public_rate']} / {params['rate_ttl']}s"
    )
    print(f"  读取接口限流         : {params['read_rate']} / {params['rate_ttl']}s")
    print(
        f"  写入接口限流         : {params['write_rate']} / {params['rate_ttl']}s"
    )
    print(f"  建议稳定在线         : 约 {params['est_stable']} 人")
    print(f"  建议瞬时峰值         : 约 {params['est_burst']} 人")
    print("=" * 60)
    print("  注意事项：")
    print("  1. 首次使用先调用 /api/login/start 扫码登录")
    print("  2. 登录后调用 /api/login/claim 获取 Bearer token")
    print("  3. 获取 token 后设置保险箱密码并解锁会话")
    print("  4. 前端有 CDN 时请正确传入 X-Client-IP 头")
    print("  5. 1 秒轮询或大量写入时承载人数请再打折")
    print("=" * 60)


# ── 第 8 步：启动服务 ─────────────────────────────────────


def start_server(venv_py: Path, params: dict):
    cmd = [
        str(venv_py),
        "-m",
        "mijiaAPI",
        "web",
        "--state_dir",
        str(_state_dir),
        "--host",
        params["host"],
        "--port",
        params["port"],
        "--max_concurrency",
        str(params["max_conc"]),
    ]
    env = os.environ.copy()
    env["MIJIA_NO_COLOR"] = "1"  # 禁用 ANSI 彩色日志，避免 Windows 终端显示乱码
    env["MIJIA_THREADPOOL_TOKENS"] = str(params["thread_pool"])
    env["MIJIA_MAX_ACTIVE_LOGIN_TASKS"] = str(params["max_login"])
    env["MIJIA_MAX_CONCURRENCY"] = str(params["max_conc"])
    env["MIJIA_PUBLIC_RATE_LIMIT"] = str(params["public_rate"])
    env["MIJIA_READ_RATE_LIMIT"] = str(params["read_rate"])
    env["MIJIA_WRITE_RATE_LIMIT"] = str(params["write_rate"])
    env["MIJIA_RATE_LIMIT_MAX_BUCKETS"] = str(params["buckets"])
    env["MIJIA_RATE_BUCKET_TTL_SECONDS"] = str(params["rate_ttl"])

    print(f"\n[8/8] 正在启动服务...")
    print("      窗口保持运行 = 服务正常运行中")
    print("      关闭本窗口 = 停止服务\n")

    sys.stdout.flush()
    try:
        subprocess.run(cmd, env=env, cwd=str(_root))
    except KeyboardInterrupt:
        print("\n服务已停止。")


# ── 主流程 ────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) < 2:
        # Auto-detect: use the directory of this script
        _root = Path(__file__).resolve().parent
    else:
        _root = Path(sys.argv[1]).resolve()
    os.chdir(str(_root))

    print("米家 API 服务 - 一键启动\n")

    try:
        step("正在检查 Python 环境...", "检查版本是否符合要求。")
        check_python()

        step(
            "正在检查状态目录...",
            "确认会话与缓存目录可写，且不在项目目录内。",
        )
        _state_dir = ensure_state_dir(_root)

        step(
            "正在检测系统资源并自动调参...",
            "检测 CPU、内存、磁盘，自动计算最优配置。",
        )
        res = detect_resources()
        params = tune_params(res)
        ok("资源检测与自动调参完成。")

        step("正在检查虚拟环境...", "自动创建或修复 .venv。")
        venv_py = setup_venv(_root)

        step("正在升级 pip 基础工具（最多重试 3 次）...")
        upgrade_pip_tools(venv_py)

        step("正在安装项目依赖（最多重试 3 次）...")
        install_project(venv_py, _root)

        step("启动摘要：")
        print_summary(res, params)

        start_server(venv_py, params)

    except Exception as e:
        print(f"\n[错误] 启动未完成: {e}")
        print("请查看上方提示后重试。")
        sys.exit(1)
