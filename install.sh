#!/bin/bash

# ═══════════════════════════════════════════════════════════════════
# ACTUATOR-REAPER Installation Script
# ═══════════════════════════════════════════════════════════════════

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}"
cat << "EOF"
╔═══════════════════════════════════════════════════════════════╗
║              ACTUATOR-REAPER Installation                     ║
║                      v1.0 Setup                               ║
╚═══════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# Check Python version
echo -e "${CYAN}[*]${NC} Checking Python version..."
python3 --version
if [ $? -ne 0 ]; then
    echo -e "${RED}[-]${NC} Python 3 is not installed!"
    exit 1
fi
echo -e "${GREEN}[+]${NC} Python 3 is installed"

# Install Python dependencies
echo -e "${CYAN}[*]${NC} Installing Python dependencies..."
pip3 install requests urllib3 --quiet
if [ $? -eq 0 ]; then
    echo -e "${GREEN}[+]${NC} Python dependencies installed"
else
    echo -e "${RED}[-]${NC} Failed to install Python dependencies"
    exit 1
fi

# Check for Go (optional)
echo -e "${CYAN}[*]${NC} Checking for Go (optional for auto-hunt mode)..."
go version 2>/dev/null
if [ $? -eq 0 ]; then
    echo -e "${GREEN}[+]${NC} Go is installed"
    
    # Install subfinder
    echo -e "${CYAN}[*]${NC} Installing subfinder..."
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[+]${NC} subfinder installed"
    fi
    
    # Install httpx
    echo -e "${CYAN}[*]${NC} Installing httpx..."
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[+]${NC} httpx installed"
    fi
    
    # Add Go bin to PATH
    export PATH=$PATH:~/go/bin
    echo -e "${YELLOW}[!]${NC} Add this to your ~/.bashrc or ~/.zshrc:"
    echo -e "    export PATH=\$PATH:~/go/bin"
else
    echo -e "${YELLOW}[!]${NC} Go is not installed (optional)"
    echo -e "${YELLOW}[!]${NC} Auto-hunt mode requires subfinder and httpx"
    echo -e "${YELLOW}[!]${NC} Manual mode will work without Go tools"
fi

# Create directories
echo -e "${CYAN}[*]${NC} Creating directories..."
mkdir -p results heapdumps
echo -e "${GREEN}[+]${NC} Directories created"

# Make script executable
echo -e "${CYAN}[*]${NC} Making actuator-reaper.py executable..."
chmod +x actuator-reaper.py
echo -e "${GREEN}[+]${NC} Script is executable"

# Final message
echo ""
echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║${NC}                    ${GREEN}Installation Complete!${NC}                    ${CYAN}║${NC}"
echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${GREEN}[+]${NC} Actuator-Reaper is ready to use!"
echo ""
echo -e "${CYAN}Quick Start:${NC}"
echo -e "  ${YELLOW}Manual Mode:${NC}"
echo -e "    python3 actuator-reaper.py -u https://target.com"
echo -e "    python3 actuator-reaper.py -f targets.txt -t 50"
echo ""
echo -e "  ${YELLOW}Auto-Hunt Mode:${NC}"
echo -e "    python3 actuator-reaper.py --auto-hunt -d programs.txt -t 100"
echo ""
echo -e "${CYAN}Documentation:${NC} Check README.md for full usage guide"
echo ""
