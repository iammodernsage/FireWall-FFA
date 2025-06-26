#!/usr/bin/env python3

import argparse
import subprocess
import yaml
import os
import signal
import sys

CONFIG_PATH = os.path.abspath("config/default.yml")
FIREWALL_BINARY = os.path.abspath("core-engine/waf")
PID_FILE = "/var/run/FireWall-FFA.pid"

def check_config():
    if not os.path.exists(CONFIG_PATH):
        print(f"[!] Config file not found: {CONFIG_PATH}")
        sys.exit(1)
    try:
        with open(CONFIG_PATH) as f:
            yaml.safe_load(f)
    except yaml.YAMLError as e:
        print(f"[!] Invalid config file: {e}")
        sys.exit(1)

def start_firewall():
    check_config()
    if os.path.exists(PID_FILE):
        print("[!] Firewall already running (PID file found).")
        return

    print("[*] Starting FireWall-FFA by Bhavesh Verma...")
    process = subprocess.Popen([FIREWALL_BINARY, "--config", CONFIG_PATH])
    with open(PID_FILE, "w") as f:
        f.write(str(process.pid))
    print(f"[+] Firewall started with PID {process.pid}")

def stop_firewall():
    if not os.path.exists(PID_FILE):
        print("[-] Firewall is not running.")
        return
    with open(PID_FILE) as f:
        pid = int(f.read().strip())
    try:
        os.kill(pid, signal.SIGTERM)
        os.remove(PID_FILE)
        print(f"[+] Stopped firewall process (PID {pid})")
    except ProcessLookupError:
        print("[!] Process not found, removing stale PID file.")
        os.remove(PID_FILE)

def reload_firewall():
    if not os.path.exists(PID_FILE):
        print("[-] Firewall is not running.")
        return
    with open(PID_FILE) as f:
        pid = int(f.read().strip())
    try:
        os.kill(pid, signal.SIGHUP)
        print(f"[+] Sent reload signal to PID {pid}")
    except ProcessLookupError:
        print("[!] Process not found, removing stale PID file.")
        os.remove(PID_FILE)

def show_status():
    if os.path.exists(PID_FILE):
        with open(PID_FILE) as f:
            pid = f.read().strip()
        print(f"[+] Firewall is running (PID {pid})")
    else:
        print("[-] Firewall is not running.")

def main():
    parser = argparse.ArgumentParser(description="FireWall-FFA CLI Tool")
    parser.add_argument("command", choices=["start", "stop", "reload", "status"], help="Firewall command")

    args = parser.parse_args()

    if args.command == "start":
        start_firewall()
    elif args.command == "stop":
        stop_firewall()
    elif args.command == "reload":
        reload_firewall()
    elif args.command == "status":
        show_status()

if __name__ == "__main__":
    main()
