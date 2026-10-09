import subprocess
import time

SERVICE_CMD = ["python3", "app.py"]
CHECK_INTERVAL = 5  # seconds


def start_service():
    return subprocess.Popen(SERVICE_CMD)


def main():
    proc = start_service()
    restarts = 0
    while True:
        time.sleep(CHECK_INTERVAL)
        if proc.poll() is not None:  # process died
            restarts += 1
            print(f"Service crashed (exit {proc.returncode}). Restart #{restarts}")
            proc = start_service()


if __name__ == "__main__":
    main()