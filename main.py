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


def main():
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
