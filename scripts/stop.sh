#!/bin/bash
# Vajra Complete Shutdown Script
#
# IMPORTANT: This restores normal networking by removing NFQUEUE rules
#
# Usage:
#   sudo ./scripts/stop.sh              # Stop everything
#   sudo ./scripts/stop.sh --keep-logs  # Stop but keep log files
#   sudo ./scripts/stop.sh --help       # Show help
#

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

KEEP_LOGS="true"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --clear-logs)
            KEEP_LOGS="false"
            shift
            ;;
        --help|-h)
            echo "Usage: sudo ./scripts/stop.sh [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --clear-logs  Clear all log files after stopping"
            echo "  --help        Show this help message"
            exit 0
            ;;
        *)
            shift
            ;;
    esac
done

echo -e "${BOLD}${YELLOW}"
echo "╔═══════════════════════════════════════════════════════════════════════╗"
echo "║                    VAJRA PIPELINE - SHUTTING DOWN                     ║"
echo "╚═══════════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Root Check
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}WARNING: Not running as root - cannot remove iptables rules${NC}"
    echo "Run: sudo ./scripts/stop.sh"
    echo ""
fi

# Step 1: Remove NFQUEUE iptables rules (CRITICAL)
echo -e "${YELLOW}[1/8] Removing NFQUEUE iptables rules...${NC}"

# Remove NFQUEUE rules - CRITICAL for restoring network
iptables -D INPUT -j NFQUEUE --queue-num 0 --queue-bypass 2>/dev/null && echo -e "${GREEN}  [OK] INPUT rule removed${NC}" || true
iptables -D OUTPUT -j NFQUEUE --queue-num 0 --queue-bypass 2>/dev/null && echo -e "${GREEN}  [OK] OUTPUT rule removed${NC}" || true
iptables -D FORWARD -j NFQUEUE --queue-num 0 --queue-bypass 2>/dev/null && echo -e "${GREEN}  [OK] FORWARD rule removed${NC}" || true

# Also try without --queue-bypass (older format)
iptables -D INPUT -j NFQUEUE --queue-num 0 2>/dev/null || true
iptables -D OUTPUT -j NFQUEUE --queue-num 0 2>/dev/null || true
iptables -D FORWARD -j NFQUEUE --queue-num 0 2>/dev/null || true

# Remove SOAR nftables blocks
if command -v nft &> /dev/null; then
    nft delete table inet vajra 2>/dev/null && echo -e "${GREEN}  [OK] nftables table inet vajra removed${NC}" || true
fi

echo -e "${GREEN}  [OK] Network restored to normal${NC}"

# Step 2: Stop Suricata
echo ""
echo -e "${YELLOW}[2/8] Stopping Suricata...${NC}"
if [ -f logs/suricata.pid ]; then
    PID=$(cat logs/suricata.pid)
    kill $PID 2>/dev/null && echo -e "${GREEN}  [OK] Stopped (PID: $PID)${NC}" || echo "  - Already stopped"
    rm -f logs/suricata.pid
else
    pkill -9 suricata 2>/dev/null && echo -e "${GREEN}  [OK] Stopped${NC}" || echo "  - Not running"
fi

# Step 3: Stop HTTP Server
echo ""
echo -e "${YELLOW}[3/8] Stopping HTTP Server...${NC}"
if [ -f logs/http_server.pid ]; then
    PID=$(cat logs/http_server.pid)
    kill $PID 2>/dev/null && echo -e "${GREEN}  [OK] Stopped (PID: $PID)${NC}" || echo "  - Already stopped"
    rm -f logs/http_server.pid
else
    pkill -f "python3 -m http.server" 2>/dev/null && echo -e "${GREEN}  [OK] Stopped${NC}" || echo "  - Not running"
fi

# Step 4: Stop SOAR Engine
echo ""
echo -e "${YELLOW}[4/8] Stopping SOAR Engine...${NC}"
if [ -f logs/soar.pid ]; then
    PID=$(cat logs/soar.pid)
    kill $PID 2>/dev/null && echo -e "${GREEN}  [OK] Stopped (PID: $PID)${NC}" || echo "  - Already stopped"
    rm -f logs/soar.pid
else
    pkill -f "vajra.soar.engine" 2>/dev/null && echo -e "${GREEN}  [OK] Stopped${NC}" || echo "  - Not running"
fi

# Step 5: Stop Unified Logger
echo ""
echo -e "${YELLOW}[5/8] Stopping Unified Logger...${NC}"
if [ -f logs/unified_logger.pid ]; then
    PID=$(cat logs/unified_logger.pid)
    kill $PID 2>/dev/null && echo -e "${GREEN}  [OK] Stopped (PID: $PID)${NC}" || echo "  - Already stopped"
    rm -f logs/unified_logger.pid
else
    pkill -f "vajra.pipeline.unified_logger" 2>/dev/null && echo -e "${GREEN}  [OK] Stopped${NC}" || echo "  - Not running"
fi

# Step 6: Stop Inference API
echo ""
echo -e "${YELLOW}[6/8] Stopping Inference API...${NC}"
if [ -f logs/inference_api.pid ]; then
    PID=$(cat logs/inference_api.pid)
    kill $PID 2>/dev/null && echo -e "${GREEN}  [OK] Stopped (PID: $PID)${NC}" || echo "  - Already stopped"
    rm -f logs/inference_api.pid
else
    pkill -f "vajra.api.inference" 2>/dev/null && echo -e "${GREEN}  [OK] Stopped${NC}" || echo "  - Not running"
fi

# Step 7: Stop Kafka Bridge
echo ""
echo -e "${YELLOW}[7/8] Stopping Kafka Bridge...${NC}"
if [ -f logs/bridge.pid ]; then
    PID=$(cat logs/bridge.pid)
    kill $PID 2>/dev/null && echo -e "${GREEN}  [OK] Stopped (PID: $PID)${NC}" || echo "  - Already stopped"
    rm -f logs/bridge.pid
else
    pkill -f "vajra.pipeline.kafka_bridge" 2>/dev/null && echo -e "${GREEN}  [OK] Stopped${NC}" || echo "  - Not running"
fi

# Step 8: Stop Packet Inspector (if running separately)
echo ""
echo -e "${YELLOW}[8/8] Stopping Packet Inspector...${NC}"
if [ -f logs/packet_inspector.pid ]; then
    PID=$(cat logs/packet_inspector.pid)
    kill $PID 2>/dev/null && echo -e "${GREEN}  [OK] Stopped (PID: $PID)${NC}" || echo "  - Already stopped"
    rm -f logs/packet_inspector.pid
else
    pkill -f "vajra.inspection.packet_inspector" 2>/dev/null && echo -e "${GREEN}  [OK] Stopped${NC}" || echo "  - Not running"
fi

# Optional: Clear logs
if [ "$KEEP_LOGS" = "false" ]; then
    echo ""
    echo -e "${YELLOW}Clearing log files...${NC}"
    rm -f logs/*.log logs/*.json logs/*.out 2>/dev/null
    echo -e "${GREEN}  [OK] Logs cleared${NC}"
fi

# Final Summary
echo ""
echo -e "${BOLD}${GREEN}"
echo "╔═══════════════════════════════════════════════════════════════════════╗"
echo "║               VAJRA PIPELINE STOPPED - NETWORK RESTORED               ║"
echo "╚═══════════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

echo -e "${GREEN}[OK]${NC} All services stopped"
echo -e "${GREEN}[OK]${NC} NFQUEUE rules removed"
echo -e "${GREEN}[OK]${NC} Normal networking restored"
echo ""
echo -e "To start again: ${CYAN}sudo ./scripts/start.sh${NC}"
echo ""
