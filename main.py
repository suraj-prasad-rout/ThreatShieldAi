"""
ThreatShield AI — Entry Point
Compatible with old style:  python main.py
New background mode:        python main.py --background
                            python main.py --daemon

Behavior:
  Normal launch (double-click / no flags):
    - Enforce single instance via mutex
    - If already running → bring existing UI to front → exit
    - If not running     → first_run_setup + start daemon + show UI

  --background / --daemon:
    - Enforce single instance
    - first_run_setup + start daemon + NO UI window
    - Shields run silently, tray icon available
    - Used by Windows startup registry
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def _fix_ssl_for_frozen_exe():
    """
    In a PyInstaller frozen EXE, Python cannot find SSL certificates
    automatically. This causes IMAP (email shield) to silently fail
    with SSL errors. We point ssl/certifi to the bundled certs.
    This must run BEFORE any network connections are made.
    """
    if not getattr(sys, 'frozen', False):
        return  # only needed in frozen EXE, not in python main.py
    try:
        import certifi
        cert_file = certifi.where()
        os.environ['SSL_CERT_FILE'] = cert_file
        os.environ['REQUESTS_CA_BUNDLE'] = cert_file
    except Exception:
        pass  # certifi not bundled — ssl will use system certs


def main():
    _fix_ssl_for_frozen_exe()   # must be first — fixes email IMAP SSL in EXE
    args = sys.argv[1:]
    background = "--background" in args or "--daemon" in args

    # ── single instance check ─────────────────────────────────────────────
    try:
        from app.launcher import enforce_single_instance
        if not enforce_single_instance():
            # already running — existing instance will show UI
            sys.exit(0)
    except Exception:
        pass  # fail open — allow launch

    # ── first run setup ───────────────────────────────────────────────────
    # works same as old: from app.launcher import first_run_setup
    from app.launcher import first_run_setup
    first_run_setup()

    # ── start daemon ──────────────────────────────────────────────────────
    from core.daemon import ThreatShieldDaemon
    daemon = ThreatShieldDaemon()

    # run(show_ui=True)  → old behavior: start shields + show UI
    # run(show_ui=False) → new behavior: start shields silently, tray only
    daemon.run(show_ui=not background)


if __name__ == "__main__":
    main()
