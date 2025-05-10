#!/bin/bash

# Colors
RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
BLUE="\033[0;34m"
NC="\033[0m"

echo -e "${BLUE}[*] Enter install path (default: /usr/local/share):${NC}"
read -r install_path
install_path="${install_path:-/usr/local/share}"

PROJECT_NAME="kwall"
TARGET_DIR="$install_path/$PROJECT_NAME"

echo -e "${YELLOW}[*] Installing to: $TARGET_DIR${NC}"

# Copy files
sudo mkdir -p "$TARGET_DIR"
sudo cp -r . "$TARGET_DIR" 2>/dev/null

# Symlink
echo -e "${BLUE}[*] Creating symlink in /usr/local/bin...${NC}"
sudo ln -sf "$TARGET_DIR/kwall" /usr/local/bin/kwall

# Create systemd service
echo -e "${BLUE}[*] Creating systemd service...${NC}"
sudo tee /etc/systemd/system/kwall.service >/dev/null <<EOF
[Unit]
Description=Kwall Service
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/usr/local/share/kwall
ExecStart=/usr/local/share/kwall/kwall start
ExecStop=/usr/local/share/kwall/kwall stop
StandardOutput=append:/usr/local/share/kwall/logs/service.log
StandardError=append:/usr/local/share/kwall/logs/service-error.log

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd
echo -e "${BLUE}[*] Enabling and reloading systemd...${NC}"
sudo systemctl daemon-reexec
sudo systemctl daemon-reload
sudo systemctl enable kwall.service

# Install backend and frontend dependencies silently
echo -e "${BLUE}[*] Installing backend dependencies...${NC}"
(cd "$TARGET_DIR/backend" && pip3 install -r requirements.txt --quiet --break-system-packages)

echo -e "${BLUE}[*] Installing frontend dependencies...${NC}"
(cd "$TARGET_DIR/frontend" && npm install --silent)

echo -e "${GREEN}[+] Setup complete.${NC}"
echo -e "${BLUE}[*] Starting K-Wall service . . .${NC}"
sudo systemctl start kwall
echo -e "${GREEN}[+] K-Wall initialised successfully.${NC}"
echo -e "${GREEN}[+] K-Wall will be running on system boot from now on.${NC}"

