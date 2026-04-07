"""
ThreatShield AI — Logger
Works both in development (E:\Threatshield\) and
when bundled as EXE (dist\ThreatShield\_internal\)
"""
import logging
import sys
import os
from pathlib import Path


def get_base_dir() -> Path:
    """
    Get the correct base directory whether running:
    - As Python script: E:\Threatshield\
    - As PyInstaller EXE: dist\ThreatShield\_internal\
    """
    if getattr(sys, 'frozen', False):
        # running as bundled EXE
        # sys.executable = dist\ThreatShield\ThreatShield.exe
        # data should be next to the exe
        return Path(sys.executable).parent
    else:
        # running as Python script
        return Path(__file__).parent.parent


BASE_DIR = get_base_dir()
DATA_DIR = BASE_DIR / "data"

# create data dir if it doesn't exist
DATA_DIR.mkdir(parents=True, exist_ok=True)

LOG_FILE = DATA_DIR / "threatshield.log"


def get_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(f"threatshield.{name}")

    if logger.handlers:
        return logger

    logger.setLevel(logging.DEBUG)

    fmt = logging.Formatter(
        "%(asctime)s.%(msecs)03d [%(name)s] %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # file handler
    try:
        fh = logging.FileHandler(str(LOG_FILE), encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(fmt)
        logger.addHandler(fh)
    except Exception:
        pass

    # console handler
    try:
        ch = logging.StreamHandler(sys.stdout)
        ch.setLevel(logging.INFO)
        ch.setFormatter(fmt)
        # safe encoding for Windows terminal
        if hasattr(ch.stream, 'reconfigure'):
            try:
                ch.stream.reconfigure(encoding='utf-8', errors='replace')
            except Exception:
                pass
        logger.addHandler(ch)
    except Exception:
        pass

    return logger
