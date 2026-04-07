"""
ThreatShield AI — Application Launcher
Merged: old functionality (first_run_setup, Linux, get_exe_path)
      + new features (single-instance mutex, --background startup flag)
"""
import sys
import os
import platform
import ctypes
from pathlib import Path
from core.logger import get_logger, BASE_DIR

log = get_logger("launcher")
PLATFORM = platform.system()

APP_NAME = "ThreatShieldAI"
MUTEX_NAME = "Global\\ThreatShieldAI_SingleInstance"

# ── single instance ───────────────────────────────────────────────────────────


def enforce_single_instance() -> bool:
    """
    Returns True  = this IS the first instance, proceed normally.
    Returns False = another instance already running; signal it and exit.
    Uses a Windows named mutex — survives process lifecycle.
    """
    if PLATFORM != "Windows":
        return True
    try:
        mutex = ctypes.windll.kernel32.CreateMutexW(
            None, False, MUTEX_NAME)
        err = ctypes.windll.kernel32.GetLastError()
        if err == 183:          # ERROR_ALREADY_EXISTS
            log.info("ThreatShield already running — bringing UI to front")
            _signal_existing_instance()
            return False
        return True
    except Exception as e:
        log.debug(f"Mutex error: {e}")
        return True             # fail open — allow launch


def _signal_existing_instance():
    """Bring the already-running ThreatShield window to front."""
    try:
        hwnd = ctypes.windll.user32.FindWindowW(None, "ThreatShield AI")
        if hwnd:
            ctypes.windll.user32.ShowWindow(hwnd, 9)    # SW_RESTORE
            ctypes.windll.user32.SetForegroundWindow(hwnd)
            log.info("Brought existing UI to front")
    except Exception as e:
        log.debug(f"Signal existing: {e}")


# ── exe / script path ─────────────────────────────────────────────────────────

def get_exe_path() -> str:
    """Return the command string used to launch ThreatShield."""
    if getattr(sys, "frozen", False):
        # Packaged EXE — use --background so it starts silently on boot
        return f'"{sys.executable}" --background'
    else:
        # Dev mode — run via Python interpreter
        python = sys.executable
        script = str(BASE_DIR / "main.py")
        return f'"{python}" "{script}" --background'


# ── startup registration ──────────────────────────────────────────────────────

def register_startup():
    """Register ThreatShield to run silently on system startup."""
    if PLATFORM == "Windows":
        _register_startup_windows()
    elif PLATFORM == "Linux":
        _register_startup_linux()


def unregister_startup():
    """Remove ThreatShield from system startup."""
    if PLATFORM == "Windows":
        _unregister_startup_windows()
    elif PLATFORM == "Linux":
        _unregister_startup_linux()


def is_registered_startup() -> bool:
    if PLATFORM == "Windows":
        return _check_startup_windows()
    elif PLATFORM == "Linux":
        return _check_startup_linux()
    return False


def _register_startup_windows():
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(
            key, APP_NAME, 0,
            winreg.REG_SZ, get_exe_path())
        winreg.CloseKey(key)
        log.info(f"Registered for Windows startup: {get_exe_path()}")
    except Exception as e:
        log.error(f"Startup registration failed: {e}")


def _unregister_startup_windows():
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            0, winreg.KEY_SET_VALUE)
        try:
            winreg.DeleteValue(key, APP_NAME)
            log.info("Removed from Windows startup")
        except FileNotFoundError:
            pass
        winreg.CloseKey(key)
    except Exception as e:
        log.error(f"Startup removal failed: {e}")


def _check_startup_windows() -> bool:
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            0, winreg.KEY_READ)
        val, _ = winreg.QueryValueEx(key, APP_NAME)
        winreg.CloseKey(key)
        return bool(val)
    except Exception:
        return False


def _register_startup_linux():
    try:
        autostart = Path.home() / ".config" / "autostart"
        autostart.mkdir(parents=True, exist_ok=True)
        desktop = autostart / "threatshield.desktop"
        desktop.write_text(
            "[Desktop Entry]\n"
            "Type=Application\n"
            "Name=ThreatShield AI\n"
            f"Exec={get_exe_path()}\n"
            "Hidden=false\n"
            "X-GNOME-Autostart-enabled=true\n")
        log.info(f"Registered Linux autostart: {desktop}")
    except Exception as e:
        log.error(f"Linux startup registration failed: {e}")


def _unregister_startup_linux():
    try:
        desktop = (Path.home() / ".config" / "autostart" /
                   "threatshield.desktop")
        desktop.unlink(missing_ok=True)
        log.info("Removed Linux autostart")
    except Exception as e:
        log.error(f"Linux startup removal failed: {e}")


def _check_startup_linux() -> bool:
    return (Path.home() / ".config" / "autostart" /
            "threatshield.desktop").exists()


# ── first-run setup ───────────────────────────────────────────────────────────

def first_run_setup():
    """
    One-time setup on first launch.
    Called by old main.py style: first_run_setup() before daemon.run()
    Also called internally by new main.py.
    """
    setup_flag = BASE_DIR / "data" / ".setup_complete"
    if setup_flag.exists():
        return

    log.info("First run — running setup...")

    # create required data directories
    for sub in ["quarantine", "sandbox_reports", "sandbox_extract"]:
        (BASE_DIR / "data" / sub).mkdir(parents=True, exist_ok=True)

    # register to start with Windows/Linux
    register_startup()

    setup_flag.touch()
    log.info("First run setup complete")

    try:
        from utils.notifier import notify
        notify("ThreatShield AI",
               "Setup complete! ThreatShield will protect you automatically.")
    except Exception:
        pass
