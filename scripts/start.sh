#!/bin/bash
# Vajra Complete Startup Script
# 
# This script starts the ENTIRE Vajra pipeline in a single command:
#   1. System Setup (install.sh, setup_venv.sh)
#   2. Python Virtual Environment Setup
#   3. Suricata IDS/IPS (NFQUEUE mode)
#   4. HTTP Server (demo attack target)
#   5. SOAR Engine (with ML and Packet Inspection)
#   6. Unified Logger
#   7. Inference API (for Federated Learning)
#   8. Kafka Bridge (optional)
#
# Usage:
#   sudo ./scripts/start.sh              # Start everything
#   sudo ./scripts/start.sh --no-http    # Skip HTTP server
#   sudo ./scripts/start.sh --help       # Show help
#

set -e

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"
export PYTHONPATH="$ROOT_DIR/src${PYTHONPATH:+:$PYTHONPATH}"

# Initial Setup Phase

# Check if this is first run (no venv exists)
FIRST_RUN=false
if [ ! -d "venv" ] && [ ! -d "venv_test" ]; then
    FIRST_RUN=true
fi

if [ "$FIRST_RUN" = true ]; then
    echo "================================================================"
    echo "First run detected - performing initial setup..."
    echo "================================================================"
    
    # Step 1: Run install.sh
    echo ""
    echo "[Setup 1/4] Running install.sh..."
    if [ -f "scripts/install.sh" ]; then
        chmod +x scripts/install.sh
        ./scripts/install.sh
        echo "[OK] install.sh completed"
    else
        echo "[WARN] install.sh not found, skipping..."
    fi
    
    # Step 2: Run setup_venv.sh
    echo ""
    echo "[Setup 2/4] Running setup_venv.sh..."
    if [ -f "scripts/setup_venv.sh" ]; then
        chmod +x scripts/setup_venv.sh
        ./scripts/setup_venv.sh
        echo "[OK] setup_venv.sh completed"
    else
        echo "[WARN] setup_venv.sh not found, skipping..."
    fi
    
    # Step 3: Create Python virtual environment
    echo ""
    echo "[Setup 3/4] Creating Python virtual environment..."
    python3 -m venv venv
    echo "[OK] Virtual environment created"
    
    # Step 4: Install requirements
    echo ""
    echo "[Setup 4/4] Installing Python requirements..."
    source venv/bin/activate
    if [ -f "requirements.txt" ]; then
        pip install --upgrade pip
        pip install -r requirements.txt
        echo "[OK] Requirements installed"
    else
        echo "[WARN] requirements.txt not found, skipping..."
    fi
    deactivate
    
    echo ""
    echo "================================================================"
    echo "Initial setup completed successfully!"
    echo "================================================================"
    echo ""
    sleep 2
fi

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Configuration - ALWAYS ENABLED
ENABLE_ML="true"
ENABLE_PACKET_INSPECTION="true"  # Always enabled as requested
ENABLE_HTTP_SERVER="true"
SOAR_DRY_RUN="false"
ENABLE_INFERENCE_API="true"
ML_MODELS_DIR="${ML_MODELS_DIR:-models}"
HTTP_PORT="${HTTP_PORT:-80}"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --no-http)
            ENABLE_HTTP_SERVER="false"
            shift
            ;;
        --dry-run)
            SOAR_DRY_RUN="true"
            shift
            ;;
        --no-api)
            ENABLE_INFERENCE_API="false"
            shift
            ;;
        --help|-h)
            echo "Usage: sudo ./scripts/start.sh [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --no-http    Skip starting HTTP server"
            echo "  --no-api     Skip starting Inference API"
            echo "  --dry-run    Log SOAR block decisions without changing the firewall"
            echo "  --help       Show this help message"
            echo ""
            echo "Environment Variables (optional - all are auto-detected):"
            echo "  VAJRA_INTERFACE     Network interface (auto-detected if not set)"
            echo "  HTTP_PORT           HTTP server port (default: 80)"
            echo "  ML_MODELS_DIR       ML models directory (default: models)"
            echo ""
            echo "The script automatically detects:"
            echo "  - Active network interface"
            echo "  - Local IP address"
            echo "  - Network CIDR for Suricata"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Run: ./scripts/start.sh --help"
            exit 1
            ;;
    esac
done

# Banner
echo -e "${BOLD}${CYAN}Starting pipeline (Linux, inline IPS mode)${NC}"
echo ""

# Root Check
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}ERROR: Must run as root for IPS mode${NC}"
    echo "Run: sudo ./scripts/start.sh"
    exit 1
fi

# Virtual Environment Detection
# Check if we're in a venv and preserve it for sudo
if [ -n "$VIRTUAL_ENV" ]; then
    PYTHON_CMD="$VIRTUAL_ENV/bin/python3"
    echo -e "${GREEN}Using virtual environment: $VIRTUAL_ENV${NC}"
elif [ -f "venv/bin/python3" ]; then
    PYTHON_CMD="$ROOT_DIR/venv/bin/python3"
    echo -e "${GREEN}Using venv: $ROOT_DIR/venv${NC}"
elif [ -f "venv_test/bin/python3" ]; then
    PYTHON_CMD="$ROOT_DIR/venv_test/bin/python3"
    echo -e "${GREEN}Using venv_test: $ROOT_DIR/venv_test${NC}"
else
    PYTHON_CMD="python3"
    echo -e "${YELLOW}Using system Python${NC}"
fi

# Create Directories (use absolute paths)
LOGS_DIR="$ROOT_DIR/logs"
RULES_DIR="$ROOT_DIR/rules"
ML_MODELS_DIR="$ROOT_DIR/${ML_MODELS_DIR:-models}"
FL_MODELS_DIR="$ROOT_DIR/fl_models"

mkdir -p "$LOGS_DIR" "$LOGS_DIR/reports" "$ML_MODELS_DIR" "$FL_MODELS_DIR" "$RULES_DIR"
chmod 755 "$LOGS_DIR" "$ML_MODELS_DIR" "$FL_MODELS_DIR" "$RULES_DIR"

echo -e "${GREEN}  [OK] Directories ready${NC}"

# Get Network Info - AUTO DETECTION

# Auto-detect network interface
auto_detect_interface() {
    # Method 1: Get interface from default route
    local iface=$(ip route show default 2>/dev/null | grep -oP 'dev\s+\K\S+' | head -1)
    if [ -n "$iface" ] && [ "$iface" != "lo" ]; then
        echo "$iface"
        return
    fi
    
    # Method 2: Get first interface with global IP
    iface=$(ip -o addr show 2>/dev/null | grep 'scope global' | head -1 | awk '{print $2}')
    if [ -n "$iface" ] && [ "$iface" != "lo" ]; then
        echo "$iface"
        return
    fi
    
    # Method 3: Check common interfaces
    for check_iface in eth0 enp0s3 enp0s5 enp0s8 ens3 ens33 wlan0; do
        if [ -d "/sys/class/net/$check_iface" ]; then
            state=$(cat /sys/class/net/$check_iface/operstate 2>/dev/null)
            if [ "$state" = "up" ]; then
                echo "$check_iface"
                return
            fi
        fi
    done
    
    # Fallback: first non-lo interface
    for check_iface in $(ls /sys/class/net 2>/dev/null); do
        if [ "$check_iface" != "lo" ]; then
            echo "$check_iface"
            return
        fi
    done
    
    echo "eth0"
}

# Auto-detect IP address
auto_detect_ip() {
    local iface=$1
    
    # Method 1: Get IP from interface
    local ip=$(ip -4 addr show $iface 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
    if [ -n "$ip" ]; then
        echo "$ip"
        return
    fi
    
    # Method 2: hostname -I
    ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    if [ -n "$ip" ] && [[ ! "$ip" =~ ^127\. ]]; then
        echo "$ip"
        return
    fi
    
    # Fallback
    echo "127.0.0.1"
}

# Use environment variable if set, otherwise auto-detect
if [ -n "$VAJRA_INTERFACE" ]; then
    INTERFACE="$VAJRA_INTERFACE"
    echo -e "${BLUE}Using environment interface: $INTERFACE${NC}"
else
    INTERFACE=$(auto_detect_interface)
    echo -e "${BLUE}Auto-detected interface: $INTERFACE${NC}"
fi

IFACE_IP=$(auto_detect_ip $INTERFACE)

# Detect network CIDR for Suricata
NETWORK_CIDR=$(ip -4 addr show $INTERFACE 2>/dev/null | grep -oP '\d+(\.\d+){3}/\d+' | head -1)
if [ -z "$NETWORK_CIDR" ]; then
    # Fallback: guess /24
    NETWORK_PREFIX=$(echo $IFACE_IP | cut -d. -f1-3)
    NETWORK_CIDR="${NETWORK_PREFIX}.0/24"
fi

echo -e "${BLUE}Network Configuration (Auto-Detected):${NC}"
echo -e "  Interface: ${YELLOW}$INTERFACE${NC}"
echo -e "  IP Address: ${YELLOW}$IFACE_IP${NC}"
echo -e "  Network: ${YELLOW}$NETWORK_CIDR${NC}"
echo ""


# Kill Existing Processes
echo -e "${YELLOW}[0/8] Cleaning up existing processes...${NC}"
# Suricata renames itself Suricata-Main, so stop it by the PID file it wrote
if [ -f "$LOGS_DIR/suricata.pid" ]; then
    kill -9 "$(cat "$LOGS_DIR/suricata.pid")" 2>/dev/null || true
    rm -f "$LOGS_DIR/suricata.pid"
fi
pkill -f "vajra.soar.engine" 2>/dev/null || true
pkill -f "vajra.pipeline.unified_logger" 2>/dev/null || true
pkill -f "vajra.pipeline.kafka_bridge" 2>/dev/null || true
pkill -f "vajra.inspection.packet_inspector" 2>/dev/null || true
pkill -f "vajra.api.inference" 2>/dev/null || true
pkill -f "uvicorn.*eve_watcher" 2>/dev/null || true
pkill -f "vajra.pipeline.eve_watcher" 2>/dev/null || true
pkill -f "python3 -m http.server" 2>/dev/null || true
sleep 2
echo -e "${GREEN}  [OK] Cleanup complete${NC}"

# Step 1: Setup NFQUEUE iptables rules
echo ""
echo -e "${YELLOW}[1/8] Setting up NFQUEUE iptables rules...${NC}"

# Clear any existing NFQUEUE rules
iptables -D INPUT -j NFQUEUE --queue-num 0 2>/dev/null || true
iptables -D OUTPUT -j NFQUEUE --queue-num 0 2>/dev/null || true
iptables -D FORWARD -j NFQUEUE --queue-num 0 2>/dev/null || true
iptables -D INPUT -j NFQUEUE --queue-num 0 --queue-bypass 2>/dev/null || true
iptables -D OUTPUT -j NFQUEUE --queue-num 0 --queue-bypass 2>/dev/null || true
iptables -D FORWARD -j NFQUEUE --queue-num 0 --queue-bypass 2>/dev/null || true

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Route ALL traffic through NFQUEUE (queue 0) for Suricata IPS
iptables -I INPUT -j NFQUEUE --queue-num 0 --queue-bypass
iptables -I OUTPUT -j NFQUEUE --queue-num 0 --queue-bypass
iptables -I FORWARD -j NFQUEUE --queue-num 0 --queue-bypass

echo -e "${GREEN}  [OK] NFQUEUE rules configured${NC}"

# Step 1.5: Generate suricata.yaml with detected interface
echo ""
echo -e "${YELLOW}[1.5/8] Generating suricata.yaml with detected interface...${NC}"

cat > "$ROOT_DIR/config/suricata/suricata.runtime.yaml" << EOF
%YAML 1.1
---
# Suricata IPS Mode Configuration - AUTO-GENERATED (Linux)
# Interface: $INTERFACE
# Network: $NETWORK_CIDR
# Generated: $(date)

vars:
  address-groups:
    HOME_NET: "[$NETWORK_CIDR,192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"
    EXTERNAL_NET: "any"
    HTTP_SERVERS: "\$HOME_NET"
    SQL_SERVERS: "\$HOME_NET"
    DNS_SERVERS: "\$HOME_NET"
    TELNET_SERVERS: "\$HOME_NET"
    SSH_SERVERS: "\$HOME_NET"
    SMTP_SERVERS: "\$HOME_NET"
  port-groups:
    HTTP_PORTS: "80,8080,443"
    SSH_PORTS: 22
    FTP_PORTS: 21
    DNS_PORTS: 53

default-log-dir: $LOGS_DIR

stats:
  enabled: yes
  interval: 10

outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      community-id: true
      pcap-file: false
      types:
        - alert:
            tagged-packets: yes
        - drop:
            alerts: yes
        - http:
            extended: yes
        - dns:
            query: yes
            answer: yes
        - tls:
            extended: yes
        - flow:
            enabled: yes
        - netflow:
            enabled: no
        - anomaly:
            enabled: yes
            types:
              - decode
              - stream
              - applayer
        - stats:
            totals: yes
            threads: yes
            deltas: yes

  - fast:
      enabled: yes
      filename: fast.log

  - drop:
      enabled: yes
      filename: drop.log

  - stats:
      enabled: yes
      filename: stats.log

# NFQUEUE mode for IPS
nfqueue:
  mode: accept
  fail-open: yes
  
# af-packet for IDS fallback
af-packet:
  - interface: $INTERFACE
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes

pcap:
  - interface: $INTERFACE

# Rules
default-rule-path: $ROOT_DIR
rule-files:
  - $RULES_DIR/local.rules

classification-file: $ROOT_DIR/config/suricata/classification.config
reference-config-file: $ROOT_DIR/config/suricata/reference.config
app-layer:
  protocols:
    http:
      enabled: yes
      libhtp:
        default-config:
          personality: IDS
          request-body-limit: 100kb
          response-body-limit: 100kb
          request-body-inspect-window: 4kb
          response-body-inspect-window: 16kb
    tls:
      enabled: yes
      detection-ports:
        dp: 443
    dns:
      tcp:
        enabled: yes
        detection-ports:
          dp: 53
      udp:
        enabled: yes
        detection-ports:
          dp: 53
    ssh:
      enabled: yes
    ftp:
      enabled: yes
    smtp:
      enabled: yes

detect:
  profile: medium
  sgh-mpm-context: auto
  inspection-recursion-limit: 3000

stream:
  memcap: 128mb
  checksum-validation: no
  inline: auto
  # Pick up flows that were open before Suricata started, such as the SSH session running this script
  midstream: true
  midstream-policy: ignore
  reassembly:
    memcap: 256mb
    depth: 1mb

flow:
  memcap: 128mb
  hash-size: 65536
  prealloc: 10000

host:
  memcap: 32mb
  hash-size: 4096
  prealloc: 1000

defrag:
  memcap: 32mb
  hash-size: 65536
  prealloc: 1000

logging:
  default-log-level: info
  default-output-filter:
  outputs:
    - console:
        enabled: yes
        type: json
    - file:
        enabled: yes
        level: info
        filename: suricata.log

coredump:
  max-dump: unlimited

host-mode: auto

unix-command:
  enabled: no
EOF

echo -e "${GREEN}  [OK] Generated config/suricata/suricata.runtime.yaml for interface: $INTERFACE${NC}"

# Step 2: Start Suricata IPS

echo ""
echo -e "${YELLOW}[2/8] Starting Suricata in IPS mode (NFQUEUE)...${NC}"

# Clear eve.json to ensure we see fresh events
echo "[]" > "$LOGS_DIR/eve.json" 2>/dev/null || true

# Start Suricata in NFQUEUE (IPS) mode with runtime config (absolute paths)
echo -e "${BLUE}  Starting: suricata -c config/suricata/suricata.runtime.yaml -q 0${NC}"
suricata -c "$ROOT_DIR/config/suricata/suricata.runtime.yaml" -q 0 -l "$LOGS_DIR" -vv -D --pidfile "$LOGS_DIR/suricata.pid" 2>&1 | tee "$LOGS_DIR/suricata_startup.log"

sleep 4

if [ -f "$LOGS_DIR/suricata.pid" ] && kill -0 "$(cat "$LOGS_DIR/suricata.pid")" 2>/dev/null; then
    SURI_PID=$(cat "$LOGS_DIR/suricata.pid")
    echo -e "${GREEN}  [OK] Suricata IPS running (PID: $SURI_PID)${NC}"
    echo -e "${BLUE}    Mode: NFQUEUE on queue 0${NC}"
    
    # Verify eve.json is being written
    sleep 2
    if [ -f "$LOGS_DIR/eve.json" ] && [ -s "$LOGS_DIR/eve.json" ]; then
        echo -e "${GREEN}  [OK] eve.json is being written${NC}"
    else
        echo -e "${YELLOW}  [WARN] eve.json not yet populated (may take a few seconds)${NC}"
    fi
else
    echo -e "${RED}  [FAIL] Suricata failed to start${NC}"
    echo "Check $LOGS_DIR/suricata.log and $LOGS_DIR/suricata_startup.log for errors"
    echo ""
    echo "Startup log:"
    tail -20 "$LOGS_DIR/suricata_startup.log" 2>/dev/null || echo "No startup log available"
    # Cleanup iptables on failure
    iptables -D INPUT -j NFQUEUE --queue-num 0 --queue-bypass 2>/dev/null || true
    iptables -D OUTPUT -j NFQUEUE --queue-num 0 --queue-bypass 2>/dev/null || true
    iptables -D FORWARD -j NFQUEUE --queue-num 0 --queue-bypass 2>/dev/null || true
    exit 1
fi

# Step 3: Start HTTP Server (demo attack target)
echo ""
if [ "$ENABLE_HTTP_SERVER" = "true" ]; then
    echo -e "${YELLOW}[3/8] Starting HTTP Server on port $HTTP_PORT...${NC}"
    
    # Serve a dedicated demo directory, never the repository itself
    mkdir -p "$LOGS_DIR/www"
    echo "Vajra demo target" > "$LOGS_DIR/www/index.html"
    nohup $PYTHON_CMD -m http.server $HTTP_PORT --directory "$LOGS_DIR/www" > logs/http_server.out 2>&1 &
    HTTP_PID=$!
    echo $HTTP_PID > logs/http_server.pid
    sleep 1
    
    if ps -p $HTTP_PID > /dev/null 2>&1; then
        echo -e "${GREEN}  [OK] HTTP Server started (PID: $HTTP_PID)${NC}"
        echo -e "${BLUE}    URL: http://$IFACE_IP:$HTTP_PORT${NC}"
    else
        echo -e "${YELLOW}  [WARN] HTTP Server failed (may need different port)${NC}"
    fi
else
    echo -e "${YELLOW}[3/8] HTTP Server skipped (--no-http)${NC}"
fi

# Step 4: Start Unified Logger
echo ""
echo -e "${YELLOW}[4/8] Starting Unified Logger...${NC}"

nohup $PYTHON_CMD -m vajra.pipeline.unified_logger > logs/unified_logger.out 2>&1 &
LOGGER_PID=$!
echo $LOGGER_PID > logs/unified_logger.pid
sleep 1

if ps -p $LOGGER_PID > /dev/null 2>&1; then
    echo -e "${GREEN}  [OK] Unified Logger started (PID: $LOGGER_PID)${NC}"
else
    echo -e "${YELLOW}  [WARN] Unified Logger failed to start${NC}"
fi

# Step 5: Start SOAR Engine (with ML and Packet Inspection)
echo ""
echo -e "${YELLOW}[5/8] Starting SOAR Engine (ML + Packet Inspection)...${NC}"

# Build SOAR command - ALWAYS enable ML and packet inspection
SOAR_CMD="$PYTHON_CMD -m vajra.soar.engine --file-mode --ml-models-dir $ML_MODELS_DIR"
SOAR_CMD="$SOAR_CMD --packet-inspection --interface $INTERFACE"
if [ "$SOAR_DRY_RUN" = "true" ]; then
    SOAR_CMD="$SOAR_CMD --dry-run"
fi

nohup $SOAR_CMD > logs/soar.out 2>&1 &
SOAR_PID=$!
echo $SOAR_PID > logs/soar.pid
sleep 2

if ps -p $SOAR_PID > /dev/null 2>&1; then
    echo -e "${GREEN}  [OK] SOAR Engine started (PID: $SOAR_PID)${NC}"
    echo -e "${BLUE}    ML Models: $ML_MODELS_DIR${NC}"
    echo -e "${BLUE}    Packet Inspection: ENABLED${NC}"
else
    echo -e "${YELLOW}  [WARN] SOAR Engine failed to start${NC}"
    echo "    Check logs/soar.out for errors"
fi

# Step 6: Start Inference API (Federated Learning)
echo ""
if [ "$ENABLE_INFERENCE_API" = "true" ]; then
    echo -e "${YELLOW}[6/8] Starting Inference API (Federated Learning)...${NC}"
    
    # Try to start inference API (will work if dependencies are installed)
    nohup $PYTHON_CMD -m vajra.api.inference > logs/inference_api.out 2>&1 &
    API_PID=$!
    echo $API_PID > logs/inference_api.pid
    sleep 3
    
    if ps -p $API_PID > /dev/null 2>&1; then
        echo -e "${GREEN}  [OK] Inference API started (PID: $API_PID)${NC}"
        echo -e "${BLUE}    URL: http://localhost:8001${NC}"
        echo -e "${BLUE}    Health: http://localhost:8001/health${NC}"
        echo -e "${BLUE}    Docs: http://localhost:8001/docs${NC}"
    else
        echo -e "${YELLOW}  [WARN] Inference API failed to start${NC}"
        echo -e "${YELLOW}    Check logs/inference_api.out for errors${NC}"
        echo -e "${YELLOW}    Install with: pip install uvicorn fastapi${NC}"
    fi
else
    echo -e "${YELLOW}[6/8] Inference API skipped (--no-api)${NC}"
fi

# Step 7: Start Eve Watcher (WebSocket stream for eve.json)
echo ""
echo -e "${YELLOW}[7/8] Starting Eve Watcher (WebSocket stream)...${NC}"

nohup $PYTHON_CMD -m vajra.pipeline.eve_watcher > logs/eve_watcher.out 2>&1 &
EVE_WATCHER_PID=$!
echo $EVE_WATCHER_PID > logs/eve_watcher.pid
sleep 2

if ps -p $EVE_WATCHER_PID > /dev/null 2>&1; then
    echo -e "${GREEN}  [OK] Eve Watcher started (PID: $EVE_WATCHER_PID)${NC}"
    echo -e "${BLUE}    WebSocket: ws://localhost:8000/ws/logs${NC}"
    echo -e "${BLUE}    Health: http://localhost:8000/health${NC}"
    echo -e "${BLUE}    Stats: http://localhost:8000/stats${NC}"
else
    echo -e "${YELLOW}  [WARN] Eve Watcher failed to start${NC}"
    echo -e "${YELLOW}    Check logs/eve_watcher.out for errors${NC}"
fi

# Step 8: Start Kafka Bridge (optional)
echo ""
echo -e "${YELLOW}[8/8] Starting Kafka Bridge...${NC}"

nohup $PYTHON_CMD -m vajra.pipeline.kafka_bridge > logs/bridge.out 2>&1 &
BRIDGE_PID=$!
echo $BRIDGE_PID > logs/bridge.pid
sleep 1

if ps -p $BRIDGE_PID > /dev/null 2>&1; then
    echo -e "${GREEN}  [OK] Kafka Bridge started (PID: $BRIDGE_PID)${NC}"
else
    echo -e "${YELLOW}  [WARN] Kafka Bridge not running (Kafka may not be available)${NC}"
fi

# Step 8: Check ML Models
echo ""
echo -e "${YELLOW}[8/8] Checking ML Models...${NC}"

# Count different model types
PKL_MODEL_COUNT=$(find "$ML_MODELS_DIR" -maxdepth 1 -name "*.pkl" -o -name "*.joblib" 2>/dev/null | wc -l | tr -d ' ')
H5_MODEL_COUNT=$(find "$ML_MODELS_DIR" -maxdepth 1 -name "*.h5" 2>/dev/null | wc -l | tr -d ' ')
TFLITE_MODEL_COUNT=$(find "$ML_MODELS_DIR" -maxdepth 1 -name "*.tflite" 2>/dev/null | wc -l | tr -d ' ')

# Count models in subdirectories (like backdoor_detection)
SUBDIR_MODEL_COUNT=$(find "$ML_MODELS_DIR" -mindepth 2 -name "*.pkl" -o -name "*.joblib" -o -name "*.h5" -o -name "*.tflite" 2>/dev/null | wc -l | tr -d ' ')

ML_MODEL_COUNT=$((PKL_MODEL_COUNT + H5_MODEL_COUNT + TFLITE_MODEL_COUNT + SUBDIR_MODEL_COUNT))

FL_MODEL_COUNT=$(find "fl_models" -name "*.pkl" -o -name "*.joblib" 2>/dev/null | wc -l | tr -d ' ')

if [ "$ML_MODEL_COUNT" -gt 0 ]; then
    echo -e "${GREEN}  [OK] Found $ML_MODEL_COUNT ML model(s) in $ML_MODELS_DIR${NC}"
    echo -e "${BLUE}    PKL/Joblib: $PKL_MODEL_COUNT, H5: $H5_MODEL_COUNT, TFLite: $TFLITE_MODEL_COUNT, Subdirs: $SUBDIR_MODEL_COUNT${NC}"
    
    # List all models
    for model in "$ML_MODELS_DIR"/*.pkl "$ML_MODELS_DIR"/*.joblib "$ML_MODELS_DIR"/*.h5 "$ML_MODELS_DIR"/*.tflite; do
        [ -f "$model" ] && echo -e "${BLUE}    - $(basename $model)${NC}"
    done 2>/dev/null
    
    # List subdirectory models
    for subdir in "$ML_MODELS_DIR"/*/; do
        if [ -d "$subdir" ]; then
            subdir_name=$(basename "$subdir")
            subdir_count=$(find "$subdir" -name "*.pkl" -o -name "*.joblib" -o -name "*.h5" -o -name "*.tflite" 2>/dev/null | wc -l | tr -d ' ')
            if [ "$subdir_count" -gt 0 ]; then
                echo -e "${BLUE}    - $subdir_name/ ($subdir_count files)${NC}"
            fi
        fi
    done 2>/dev/null
else
    echo -e "${YELLOW}  [WARN] No ML models in $ML_MODELS_DIR${NC}"
fi

if [ "$FL_MODEL_COUNT" -gt 0 ]; then
    echo -e "${GREEN}  [OK] Found $FL_MODEL_COUNT FL model(s) in fl_models/${NC}"
else
    echo -e "${YELLOW}  [WARN] No FL models in fl_models/ (run FL client to train)${NC}"
fi

# Final Summary
echo ""
echo -e "${BOLD}${GREEN}"
echo "╔═══════════════════════════════════════════════════════════════════════╗"
echo "║                     VAJRA IPS MODE ACTIVE                             ║"
echo "╚═══════════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

echo -e "${GREEN}[OK]${NC} All traffic flows through Suricata IPS"
echo -e "${GREEN}[OK]${NC} Malicious packets are ${RED}DROPPED${NC}"
echo -e "${GREEN}[OK]${NC} ML threat detection is ${GREEN}ENABLED${NC}"
echo -e "${GREEN}[OK]${NC} Packet inspection is ${GREEN}ENABLED${NC}"
echo -e "${GREEN}[OK]${NC} SOAR orchestration is ${GREEN}ACTIVE${NC}"
if [ "$ENABLE_HTTP_SERVER" = "true" ]; then
    echo -e "${GREEN}[OK]${NC} HTTP server on port ${YELLOW}$HTTP_PORT${NC}"
fi
if [ "$ENABLE_INFERENCE_API" = "true" ]; then
    echo -e "${GREEN}[OK]${NC} Inference API on port ${YELLOW}8001${NC}"
fi

echo ""
echo -e "${BOLD}Logs:${NC}"
echo "  Suricata:      logs/eve.json"
echo "  ML Predictions: logs/ml_predictions.json"
echo "  Unified Events: logs/unified_events.json"
echo "  SOAR Actions:   logs/soar_actions.log"
echo "  SOAR Engine:    logs/soar_engine.log"

echo ""
echo -e "${BOLD}Test Attack:${NC}"
echo -e "  ${CYAN}python3 tools/attack_simulator.py --target $IFACE_IP --full${NC}"

echo ""
echo -e "${BOLD}Monitor:${NC}"
echo -e "  ${CYAN}python3 scripts/status.py${NC}"
echo -e "  ${CYAN}tail -f logs/unified_events.json${NC}"

echo ""
echo -e "${BOLD}${RED}WARNING: To restore normal networking, run: sudo ./scripts/stop.sh${NC}"
echo ""
