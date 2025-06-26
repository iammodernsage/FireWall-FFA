#!/bin/bash

set -e

echo "[*] Installing FireWall-FFA by Bhavesh Verma..."

# Create bin directory
mkdir -p bin

# Compile using new engine layout
echo "[*] Compiling core-engine/waf.c with waf_rules.c and waf_engine.h..."
gcc core-engine/waf.c core-engine/waf_rules.c -o bin/waf -Wall -Icore-engine

# Copy binary back to core-engine for CLI reference
cp bin/waf core-engine/waf

chmod +x cli-tool/firewallctl.py

# Install Python dependencies
if [ -f "requirements.txt" ]; then
    echo "[*] Installing Python dependencies..."
    pip3 install -r requirements.txt
fi

read -p "[?] Install as systemd service? (y/n): " svc
if [[ "$svc" == "y" || "$svc" == "Y" ]]; then
    echo "[*] Creating systemd service file..."

    SERVICE_PATH="/etc/systemd/system/FireWall-FFA.service"
    sudo tee "$SERVICE_PATH" > /dev/null <<EOF
[Unit]
Description=FireWall-FFA WAF
After=network.target

[Service]
ExecStart=$(pwd)/core-engine/waf --config $(pwd)/config/default.yml
Restart=always
User=root
WorkingDirectory=$(pwd)
PIDFile=/var/run/FireWall-FFA.pid

[Install]
WantedBy=multi-user.target
EOF

    echo "[*] Enabling and starting FireWall-FFA service..."
    sudo systemctl daemon-reexec
    sudo systemctl enable FireWall-FFA
    sudo systemctl start FireWall-FFA
fi

echo "[+] Installation complete. Use './cli-tool/firewallctl.py start' to launch manually."
