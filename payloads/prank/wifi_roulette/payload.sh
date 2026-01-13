#!/bin/bash
# Title: WiFi Roulette (No-Spin)
# Description: Scans for targets, uses Rainbow Logs instead of Spinner, and plays a client selection game.
# Author: Gemini <user@example.com>
# Version: 1.2
# Category: Recon
# Target: WiFi Pineapple Pager
# Net Mode: NAT
# Dependencies: airodump-ng, grep, awk

# ============================================
# CONFIGURATION
# ============================================
SCAN_DURATION=30
RECON_DIR="/tmp/roulette_scan"
RECON_PREFIX="capture"
PAUSE_MIN=15
PAUSE_MAX=60

# ============================================
# HELPER FUNCTIONS
# ============================================

# Function to simulate activity without freezing UI (Rainbow Logs)
# Usage: rainbow_wait [duration_seconds] [message]
function rainbow_wait() {
    local duration=$1
    local msg=$2
    local end_time=$(( $(date +%s) + duration ))
    local colors=("red" "green" "blue" "magenta" "cyan" "yellow")
    
    LOG "Starting: $msg"
    
    while [ $(date +%s) -lt $end_time ]; do
        # Pick random color
        local rand_idx=$((RANDOM % 6))
        local col=${colors[$rand_idx]}
        
        LOG $col "$msg - Working..."
        sleep 2
    done
}

# ============================================
# INITIALIZATION
# ============================================
LOG "Starting payload: WiFi Roulette (No-Spin)"

# Clean up previous scans
rm -rf "$RECON_DIR"
mkdir -p "$RECON_DIR"

# ============================================
# RECONNAISSANCE PHASE
# ============================================
# We use PineAP to manage the environment, but airodump to capture parseable data
# because the PineAP database export isn't documented in the guide.

PINEAPPLE_RECON_NEW
PINEAPPLE_SET_BANDS "2.4,5"
PINEAPPLE_EXAMINE_RESET

# Start background capture using standard tools to ensure we get a file
# Note: Assuming 'wlan1' is the monitoring interface. If 'wlan1mon' exists, use that.
ifconfig wlan1 up 2>/dev/null

rainbow_wait $SCAN_DURATION "Scanning Area"

# Run actual data capture
LOG blue "Capturing data to file..."
# Run airodump for a set duration
timeout $SCAN_DURATION airodump-ng wlan1 --output-format csv -w "${RECON_DIR}/${RECON_PREFIX}" > /dev/null 2>&1

LOG green "Scan complete."

# ============================================
# TARGET PARSING & SELECTION
# ============================================
CSV_FILE="${RECON_DIR}/${RECON_PREFIX}-01.csv"

if [ ! -f "$CSV_FILE" ]; then
    ERROR_DIALOG "Scan failed: No data file generated."
    exit 1
fi

LOG "Parsing targets..."

# Parse CSV for SSIDs with clients
# Airodump CSV format is tricky; we look for the "Station MAC" section
# Simple approach: Find lines with SSIDs (ignoring the header)
# We will create a temporary list of detected SSIDs
target_list_file="/tmp/target_ssids.txt"
grep -a "," "$CSV_FILE" | grep -a "WPA" | awk -F',' '{print $14}' | sed 's/^ //g' | sort -u | grep -v "^$" > "$target_list_file"

# Read into array
mapfile -t TARGET_SSIDS < "$target_list_file"
target_count=${#TARGET_SSIDS[@]}

if [ "$target_count" -eq 0 ]; then
    ALERT "No SSIDs found."
    exit 0
fi

# Output list to LOG
LOG "=== Available Targets ==="
i=1
for ssid in "${TARGET_SSIDS[@]}"; do
    LOG "[$i] $ssid"
    ((i++))
done
LOG "========================="

# User Selection
sel_index=$(NUMBER_PICKER "Enter Target ID (1-$target_count)" 1)

# Validate
case $? in
    $DUCKYSCRIPT_CANCELLED) LOG "User cancelled."; exit 0 ;;
    $DUCKYSCRIPT_ERROR) ERROR_DIALOG "Input Error"; exit 1 ;;
esac

# Adjust index (1-based input to 0-based array)
array_index=$((sel_index - 1))

if [ "$array_index" -lt 0 ] || [ "$array_index" -ge "$target_count" ]; then
    ERROR_DIALOG "Invalid ID."
    exit 1
fi

SELECTED_SSID="${TARGET_SSIDS[$array_index]}"
# Strip newline/whitespace
SELECTED_SSID=$(echo "$SELECTED_SSID" | tr -d '\r\n')

LOG green "Target Locked: $SELECTED_SSID"
ALERT "Locked on:\n$SELECTED_SSID"

# ============================================
# ROULETTE GAME LOOP
# ============================================

while true; do
    
    # --- PHASE 1: PAUSE (WHITE) ---
    # Random wait 15-60s
    pause_time=$((PAUSE_MIN + RANDOM % (PAUSE_MAX - PAUSE_MIN + 1)))
    
    # Simulate "White" state with logs (Hardware LEDs not controllable via this API)
    LOG "Status: PAUSED (Waiting ${pause_time}s)"
    sleep "$pause_time"

    # --- PHASE 2: SELECTION (GREEN CIRCLING) ---
    # Rainbow logs for "Circling" effect
    rainbow_wait 5 "Selecting Winner"

    # --- PHASE 3: ACTION (RED) ---
    # Find a client associated with this SSID from the CSV
    # We grep for the BSSID associated with the SSID name, then find clients connected to that BSSID
    
    # 1. Get BSSID for the name
    TARGET_BSSID=$(grep -a "$SELECTED_SSID" "$CSV_FILE" | awk -F',' '{print $1}' | head -n 1)
    
    if [ -z "$TARGET_BSSID" ]; then
        LOG red "Lost track of BSSID."
        sleep 5
        continue
    fi
    
    # 2. Find clients in CSV that match this BSSID (Station section)
    # Airodump CSV puts clients after "Station MAC" line. 
    # We look for lines where the 6th column (BSSID) matches our target.
    mapfile -t CLIENT_LIST < <(grep -a "$TARGET_BSSID" "$CSV_FILE" | grep -v "$SELECTED_SSID" | awk -F',' '{print $1}')
    
    client_count=${#CLIENT_LIST[@]}
    
    if [ "$client_count" -gt 0 ]; then
        # Pick random client
        rand_client_idx=$((RANDOM % client_count))
        winner_mac="${CLIENT_LIST[$rand_client_idx]}"
        
        # Pick random direction for Log
        dirs=("UP" "DOWN" "LEFT" "RIGHT")
        rand_dir=${dirs[$((RANDOM % 4))]}
        
        # "RED" State for 5 seconds
        LOG red "!!! WINNER SELECTED !!!"
        LOG red "Client: $winner_mac"
        LOG red "LED Indication: $rand_dir"
        
        ALERT "Winner:\n$winner_mac"
        sleep 5
    else
        LOG red "No clients connected to target."
        sleep 2
    fi

done