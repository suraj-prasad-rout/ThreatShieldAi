"""Cross-platform desktop notifications — no dependencies on Windows/macOS."""
import platform
import subprocess

def notify(title: str, message: str):
    system = platform.system()
    try:
        if system == "Windows":
            from win10toast import ToastNotifier
            ToastNotifier().show_toast(title, message, duration=5, threaded=True)
        elif system == "Darwin":
            subprocess.run(
                ["osascript", "-e", f'display notification "{message}" with title "{title}"'],
                check=False,
            )
        else:
            subprocess.run(["notify-send", title, message], check=False)
    except Exception:
        pass    # silent fallback — notification is nice-to-have, not critical
