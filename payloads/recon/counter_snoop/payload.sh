#!/bin/bash
# Title: Counter Snoop v14.2.1 (FIXED)
# Description: MAC Aging, GPS Logging, Threat Profiles, Statistics Export
# Version: 14.2.1
# Fixes: GPS_GET parsing, infinite loop until user stops

# ==========================================
#        DEFAULT CONFIGURATION
# ==========================================
RSSI_LIMIT=-80
WALK_THRESHOLD=3
SIT_THRESHOLD=5
STATUS_INTERVAL=60

# MAC Aging Configuration
MAC_AGING_ENABLED=true
MAC_AGING_TIMEOUT=300  # Forget devices after 5 minutes of not seeing them

# GPS Configuration
GPS_ENABLED=true
GPS_LOG_INTERVAL=30  # Log GPS position every 30 seconds

# Statistics Export
STATS_EXPORT_INTERVAL=300  # Export statistics every 5 minutes

# RTTTL Patterns
VIBE_THREAT="d=4,o=5,b=200:8c,8p,8c,8p,8c"
VIBE_HEARTBEAT="d=32,o=5,b=100:32c"

# ==========================================
#        THREAT PROFILES
# ==========================================
# Define threat signatures for common tracking devices

# AirTag Signature: Frequent probe requests with randomized MAC prefix
declare -A AIRTAG_INDICATORS
AIRTAG_INDICATORS["probe_frequency"]="high"  # >10 probes per minute
AIRTAG_INDICATORS["ssid_pattern"]="<HIDDEN>"
AIRTAG_INDICATORS["vendor_oui"]=""  # Randomized, no specific OUI

# WiFi Pineapple Signature: Beacon spam with multiple SSIDs
declare -A PINEAPPLE_INDICATORS
PINEAPPLE_INDICATORS["beacon_frequency"]="high"
PINEAPPLE_INDICATORS["multiple_ssids"]="true"
PINEAPPLE_INDICATORS["deauth_present"]="possible"

# Rogue AP Signature: Strong signal AP with suspicious SSID
declare -A ROGUE_AP_INDICATORS
ROGUE_AP_INDICATORS["signal_strength"]="-60"  # Very strong
ROGUE_AP_INDICATORS["ssid_similarity"]="high"  # Similar to known networks
ROGUE_AP_INDICATORS["type"]="[AP]"

# Tile/Bluetooth Tracker Signature
declare -A BT_TRACKER_INDICATORS
BT_TRACKER_INDICATORS["type"]="[BT]"
BT_TRACKER_INDICATORS["persistence"]="high"

# ==========================================
#           CORE FUNCTIONS
# ==========================================

# 1. SETUP
if [ -f "/lib/hak5/commands.sh" ]; then source /lib/hak5/commands.sh; fi

# Define Directories
PAYLOAD_DIR="/root/user/payloads/reconnaisannce/counter_snoop"
LOOT_DIR="/root/loot/counter_snoop"
STATS_DIR="${LOOT_DIR}/statistics"
GPS_DIR="${LOOT_DIR}/gps_tracks"
mkdir -p "$LOOT_DIR" "$STATS_DIR" "$GPS_DIR"

# WHITELIST PATH
WHITELIST_FILE="${PAYLOAD_DIR}/whitelist.txt"

# RAM-based Temp Files
SCAN_WIFI="/tmp/cs_wifi.txt"
SCAN_BT="/tmp/cs_bt.txt"
COMBINED="/tmp/cs_combined.txt"

# Session identifier
SESSION_ID=$(date +%Y%m%d_%H%M%S)

# Log Files
LOG_FILE="${LOOT_DIR}/track_${SESSION_ID}.txt"
GPS_LOG="${GPS_DIR}/gps_${SESSION_ID}.csv"
STATS_FILE="${STATS_DIR}/stats_${SESSION_ID}.csv"
THREAT_PROFILE_LOG="${LOOT_DIR}/threat_profiles_${SESSION_ID}.txt"

touch "$LOG_FILE" "$THREAT_PROFILE_LOG"

# Initialize CSV files with headers
echo "Timestamp,Device_Path,Latitude,Longitude,Altitude,Speed,Tracked_Devices,Active_Threats" > "$GPS_LOG"
echo "Timestamp,MAC,Name,Type,First_Seen,Last_Seen,Count,RSSI_Avg,Threat_Profile,Alerted" > "$STATS_FILE"

# 2. HARDWARE CONTROL
start_hopper() {
    (
        while true; do
            for CH in 1 6 11 2 7 12 3 8 4 9 5 10; do
                iw dev "$IFACE_MONITOR" set channel $CH 2>/dev/null
                sleep 0.5
            done
        done
    ) &
    HOPPER_PID=$!
}

scan_bt_background() {
    (
        while true; do
            hcitool scan 2>/dev/null > "${SCAN_BT}.tmp" || true
            if [ -f "${SCAN_BT}.tmp" ]; then
                tail -n +2 "${SCAN_BT}.tmp" 2>/dev/null | awk '{print $1 " " substr($0, index($0,$2)) " [BT]"}' > "$SCAN_BT" || true
            fi
            sleep 5
        done
    ) &
    BT_PID=$!
}

# 3. GPS LOGGING (FIXED - Parse actual GPS data from device)
gps_logger() {
    (
        while true; do
            sleep "$GPS_LOG_INTERVAL"
            
            if [ "$GPS_ENABLED" = true ] && [ -n "$GPS_DEVICE" ]; then
                # Method 1: Try gpspipe (most common on Pineapples with GPS)
                if command -v gpspipe &> /dev/null; then
                    GPS_DATA=$(timeout 5 gpspipe -w -n 10 2>/dev/null | grep -m 1 '"class":"TPV"' | jq -r '[.lat,.lon,.alt,.speed] | @csv' 2>/dev/null)
                    if [ -n "$GPS_DATA" ] && [[ "$GPS_DATA" != *"null"* ]]; then
                        IFS=',' read -r LAT LON ALT SPEED <<< "$GPS_DATA"
                        # Remove quotes from jq output
                        LAT=$(echo "$LAT" | tr -d '"')
                        LON=$(echo "$LON" | tr -d '"')
                        ALT=$(echo "$ALT" | tr -d '"')
                        SPEED=$(echo "$SPEED" | tr -d '"')
                    fi
                fi
                
                # Method 2: Read NMEA sentences directly from GPS device
                if [ -z "$LAT" ] || [ "$LAT" = "null" ]; then
                    # Read GPGGA sentence for position
                    NMEA_LINE=$(timeout 3 cat "$GPS_DEVICE" 2>/dev/null | grep -m 1 '^\$GPGGA' || echo "")
                    if [ -n "$NMEA_LINE" ]; then
                        IFS=',' read -ra NMEA <<< "$NMEA_LINE"
                        if [ "${#NMEA[@]}" -gt 9 ] && [ "${NMEA[2]}" != "" ] && [ "${NMEA[4]}" != "" ]; then
                            # Parse latitude (format: DDMM.MMMM)
                            LAT_RAW="${NMEA[2]}"
                            LAT_DIR="${NMEA[3]}"
                            LAT_DEG="${LAT_RAW:0:2}"
                            LAT_MIN="${LAT_RAW:2}"
                            LAT=$(echo "scale=6; $LAT_DEG + $LAT_MIN / 60" | bc 2>/dev/null)
                            [ "$LAT_DIR" = "S" ] && LAT=$(echo "scale=6; -1 * $LAT" | bc 2>/dev/null)
                            
                            # Parse longitude (format: DDDMM.MMMM)
                            LON_RAW="${NMEA[4]}"
                            LON_DIR="${NMEA[5]}"
                            LON_DEG="${LON_RAW:0:3}"
                            LON_MIN="${LON_RAW:3}"
                            LON=$(echo "scale=6; $LON_DEG + $LON_MIN / 60" | bc 2>/dev/null)
                            [ "$LON_DIR" = "W" ] && LON=$(echo "scale=6; -1 * $LON" | bc 2>/dev/null)
                            
                            # Altitude
                            ALT="${NMEA[9]}"
                            
                            # Speed from GPRMC if available
                            SPEED="N/A"
                        fi
                    fi
                fi
                
                # If we got valid GPS data, log it
                if [ -n "$LAT" ] && [ "$LAT" != "N/A" ] && [ "$LAT" != "null" ] && [ "$LAT" != "" ]; then
                    # Count current threats
                    THREAT_COUNT=0
                    for mac in "${!MAP_ALERTED[@]}"; do
                        [ "${MAP_ALERTED[$mac]}" = "1" ] && THREAT_COUNT=$((THREAT_COUNT + 1))
                    done
                    
                    DEVICE_COUNT=${#MAP_COUNT[@]}
                    TS=$(date '+%Y-%m-%d %H:%M:%S')
                    
                    echo "$TS,$GPS_DEVICE,$LAT,$LON,${ALT:-N/A},${SPEED:-N/A},$DEVICE_COUNT,$THREAT_COUNT" >> "$GPS_LOG"
                fi
            fi
        done
    ) &
    GPS_PID=$!
}

# 4. STATISTICS EXPORTER
export_statistics() {
    TS=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Export current device statistics
    for mac in "${!MAP_COUNT[@]}"; do
        NAME="${MAP_NAME[$mac]}"
        TYPE=$(echo "$NAME" | grep -oP '\[(AP|CLI|BT)\]' || echo "[UNK]")
        FIRST="${MAP_FIRST_SEEN[$mac]}"
        LAST="${MAP_LAST_SEEN[$mac]}"
        COUNT="${MAP_COUNT[$mac]}"
        RSSI="${MAP_RSSI_AVG[$mac]:-N/A}"
        PROFILE="${MAP_THREAT_PROFILE[$mac]:-UNKNOWN}"
        ALERTED="${MAP_ALERTED[$mac]:-0}"
        
        echo "$TS,\"$mac\",\"$NAME\",$TYPE,$FIRST,$LAST,$COUNT,$RSSI,$PROFILE,$ALERTED" >> "$STATS_FILE"
    done
}

statistics_exporter() {
    (
        while true; do
            sleep "$STATS_EXPORT_INTERVAL"
            export_statistics
        done
    ) &
    STATS_PID=$!
}

# 5. MAC AGING - Forget devices not seen recently
age_macs() {
    if [ "$MAC_AGING_ENABLED" != true ]; then
        return
    fi
    
    CURRENT_TIME=$(date +%s)
    AGED_COUNT=0
    
    for mac in "${!MAP_LAST_SEEN[@]}"; do
        LAST_SEEN="${MAP_LAST_SEEN[$mac]}"
        TIME_DIFF=$((CURRENT_TIME - LAST_SEEN))
        
        if [ "$TIME_DIFF" -gt "$MAC_AGING_TIMEOUT" ]; then
            # Device hasn't been seen in a while, forget it
            unset MAP_COUNT["$mac"]
            unset MAP_NAME["$mac"]
            unset MAP_ALERTED["$mac"]
            unset MAP_FIRST_SEEN["$mac"]
            unset MAP_LAST_SEEN["$mac"]
            unset MAP_RSSI_AVG["$mac"]
            unset MAP_RSSI_SAMPLES["$mac"]
            unset MAP_THREAT_PROFILE["$mac"]
            unset MAP_PROBE_COUNT["$mac"]
            unset MAP_BEACON_COUNT["$mac"]
            
            AGED_COUNT=$((AGED_COUNT + 1))
        fi
    done
    
    if [ "$AGED_COUNT" -gt 0 ]; then
        LOG blue "Aged out $AGED_COUNT inactive devices"
    fi
}

# 6. THREAT PROFILE ANALYZER
analyze_threat_profile() {
    local mac="$1"
    local desc="$2"
    local type="$3"
    
    local profile="UNKNOWN"
    local confidence=0
    
    # Count packet types for this MAC
    local probe_count="${MAP_PROBE_COUNT[$mac]:-0}"
    local beacon_count="${MAP_BEACON_COUNT[$mac]:-0}"
    local total_count="${MAP_COUNT[$mac]:-0}"
    
    # Calculate frequencies
    local time_tracked=$(($(date +%s) - ${MAP_FIRST_SEEN[$mac]:-$(date +%s)}))
    if [ "$time_tracked" -eq 0 ]; then time_tracked=1; fi
    
    local probes_per_min=$((probe_count * 60 / time_tracked))
    local beacons_per_min=$((beacon_count * 60 / time_tracked))
    
    # AirTag / Bluetooth Tracker Detection
    if [[ "$type" == "[BT]" ]]; then
        if [ "$total_count" -ge 3 ]; then
            profile="BT_TRACKER"
            confidence=70
            
            # Check for persistent Bluetooth presence
            if [ "$total_count" -ge 5 ]; then
                confidence=85
            fi
        fi
    fi
    
    # WiFi Tracker (AirTag-like) Detection
    if [[ "$type" == "[CLI]" ]] && [[ "$desc" == *"<HIDDEN>"* ]]; then
        if [ "$probes_per_min" -gt 10 ]; then
            profile="WIFI_TRACKER"
            confidence=75
            
            # Check for randomized MAC (first octet bit pattern)
            local first_octet="${mac:0:2}"
            local first_byte=$((16#$first_octet))
            local locally_admin=$((first_byte & 2))
            
            if [ "$locally_admin" -ne 0 ]; then
                confidence=90
            fi
        fi
    fi
    
    # Rogue AP Detection
    if [[ "$type" == "[AP]" ]]; then
        local rssi_avg="${MAP_RSSI_AVG[$mac]:-0}"
        
        # Very strong signal AP
        if [ "$rssi_avg" -gt -60 ] 2>/dev/null; then
            profile="ROGUE_AP"
            confidence=60
            
            # Check for suspicious SSID patterns
            if [[ "$desc" =~ (Free|Guest|Public|WiFi|Hotel|Airport|Starbucks|McDonalds) ]]; then
                confidence=80
            fi
            
            # Very high beacon rate
            if [ "$beacons_per_min" -gt 20 ]; then
                confidence=85
            fi
        fi
    fi
    
    # WiFi Pineapple Detection
    if [[ "$type" == "[AP]" ]] && [ "$beacon_count" -gt 50 ]; then
        # Check if same MAC broadcasts multiple SSIDs (advanced, would need SSID tracking)
        profile="POTENTIAL_PINEAPPLE"
        confidence=65
    fi
    
    # Persistent Client (potential surveillance)
    if [[ "$type" == "[CLI]" ]] && [[ "$desc" != *"<HIDDEN>"* ]]; then
        if [ "$total_count" -ge 10 ]; then
            profile="PERSISTENT_CLIENT"
            confidence=70
        fi
    fi
    
    # Store profile
    MAP_THREAT_PROFILE["$mac"]="$profile"
    
    # Log high-confidence threats
    if [ "$confidence" -ge 75 ]; then
        TS=$(date '+%H:%M:%S')
        echo "$TS [PROFILE] $mac - $profile (Confidence: ${confidence}%) - $desc" >> "$THREAT_PROFILE_LOG"
        LOG yellow "🔍 Profile: $profile ($confidence%) - $desc"
    fi
    
    echo "$profile"
}

alert_threat() {
    local mac="$1"
    local profile="${MAP_THREAT_PROFILE[$mac]:-UNKNOWN}"
    
    LED R FAST
    
    # Different vibration patterns based on threat profile
    case "$profile" in
        "BT_TRACKER"|"WIFI_TRACKER")
            VIBRATE "$VIBE_THREAT"
            ;;
        "ROGUE_AP"|"POTENTIAL_PINEAPPLE")
            VIBRATE "d=4,o=5,b=200:8c,8p,8c,8p,8c,8p,8c"  # Extra beep
            ;;
        *)
            VIBRATE "$VIBE_THREAT"
            ;;
    esac
    
    (sleep 2; LED B SLOW) &
}

cleanup() {
    LOG blue "Cleaning up..."
    
    # Kill background processes
    if [ -n "$HOPPER_PID" ]; then kill "$HOPPER_PID" 2>/dev/null; wait "$HOPPER_PID" 2>/dev/null || true; fi
    if [ -n "$BT_PID" ]; then kill "$BT_PID" 2>/dev/null; wait "$BT_PID" 2>/dev/null || true; fi
    if [ -n "$GPS_PID" ]; then kill "$GPS_PID" 2>/dev/null; wait "$GPS_PID" 2>/dev/null || true; fi
    if [ -n "$STATS_PID" ]; then kill "$STATS_PID" 2>/dev/null; wait "$STATS_PID" 2>/dev/null || true; fi
    
    # Final statistics export
    export_statistics
    
    # Generate summary report
    generate_summary_report
    
    # Clean temp files
    rm -f "$SCAN_WIFI" "$SCAN_BT" "${SCAN_BT}.tmp" "$COMBINED" 2>/dev/null
    
    LED OFF
    LOG green "Payload Stopped - Logs saved to $LOOT_DIR"
    exit 0
}
trap cleanup EXIT INT TERM

# 7. NORMALIZE MAC ADDRESS
normalize_mac() {
    echo "$1" | tr -d ' \t\r\n:-' | tr '[:lower:]' '[:upper:]' | sed 's/\(..\)/\1:/g;s/:$//'
}

# 8. CALCULATE AVERAGE RSSI
update_rssi_avg() {
    local mac="$1"
    local new_rssi="$2"
    
    if [ -z "$new_rssi" ] || [ "$new_rssi" = "N/A" ]; then
        return
    fi
    
    local current_avg="${MAP_RSSI_AVG[$mac]:-0}"
    local sample_count="${MAP_RSSI_SAMPLES[$mac]:-0}"
    
    # Calculate new average
    local total=$((current_avg * sample_count))
    total=$((total + new_rssi))
    sample_count=$((sample_count + 1))
    
    MAP_RSSI_AVG["$mac"]=$((total / sample_count))
    MAP_RSSI_SAMPLES["$mac"]=$sample_count
}

# 9. GENERATE SUMMARY REPORT
generate_summary_report() {
    local SUMMARY_FILE="${LOOT_DIR}/session_summary_${SESSION_ID}.txt"
    
    {
        echo "======================================"
        echo "  COUNTER SNOOP SESSION SUMMARY"
        echo "======================================"
        echo "Session ID: $SESSION_ID"
        echo "Date: $(date '+%Y-%m-%d %H:%M:%S')"
        echo ""
        echo "Configuration:"
        echo "  RSSI Limit: $RSSI_LIMIT dBm"
        echo "  Threshold: ${THRESHOLD:-3} detections"
        echo "  MAC Aging: $MAC_AGING_ENABLED (${MAC_AGING_TIMEOUT}s timeout)"
        echo "  GPS Logging: $GPS_ENABLED"
        if [ -n "$GPS_DEVICE" ]; then
            echo "  GPS Device: $GPS_DEVICE"
        fi
        echo ""
        echo "Statistics:"
        echo "  Total Devices Tracked: ${#MAP_COUNT[@]}"
        
        # Count threats by profile
        declare -A profile_counts
        for mac in "${!MAP_THREAT_PROFILE[@]}"; do
            profile="${MAP_THREAT_PROFILE[$mac]}"
            profile_counts["$profile"]=$((${profile_counts["$profile"]:-0} + 1))
        done
        
        echo ""
        echo "Threat Profiles Detected:"
        for profile in "${!profile_counts[@]}"; do
            echo "  $profile: ${profile_counts[$profile]}"
        done
        
        # List all alerted threats
        echo ""
        echo "======================================"
        echo "  ALERTED THREATS"
        echo "======================================"
        for mac in "${!MAP_ALERTED[@]}"; do
            if [ "${MAP_ALERTED[$mac]}" = "1" ]; then
                echo "MAC: $mac"
                echo "  Name: ${MAP_NAME[$mac]}"
                echo "  Profile: ${MAP_THREAT_PROFILE[$mac]:-UNKNOWN}"
                echo "  Count: ${MAP_COUNT[$mac]}"
                echo "  Avg RSSI: ${MAP_RSSI_AVG[$mac]:-N/A} dBm"
                echo "  First Seen: $(date -d @${MAP_FIRST_SEEN[$mac]} '+%H:%M:%S' 2>/dev/null || echo 'N/A')"
                echo "  Last Seen: $(date -d @${MAP_LAST_SEEN[$mac]} '+%H:%M:%S' 2>/dev/null || echo 'N/A')"
                echo ""
            fi
        done
        
        echo "======================================"
        echo "Log Files:"
        echo "  Main Log: $LOG_FILE"
        echo "  GPS Track: $GPS_LOG"
        echo "  Statistics: $STATS_FILE"
        echo "  Threat Profiles: $THREAT_PROFILE_LOG"
        echo "======================================"
    } > "$SUMMARY_FILE"
    
    LOG green "Summary report: $SUMMARY_FILE"
}

# ==========================================
#        STARTUP & INTERACTION
# ==========================================

# 1. MONITOR INTERFACE CHECK
IFACE_MONITOR=$(iw dev | awk '$1=="Interface" && $2 ~ /mon/{print $2}' | head -n 1)
if [ -z "$IFACE_MONITOR" ]; then
    LED R SOLID
    LOG red "ERROR: No Monitor Interface"
    exit 1
fi

LOG blue "Monitor Interface: $IFACE_MONITOR"

# 2. CHECK GPS AVAILABILITY (FIXED - Parse GPS_GET output to find device)
GPS_DEVICE=""
if command -v GPS_GET &> /dev/null; then
    # GPS_GET lists GPS devices, extract the device path
    GPS_OUTPUT=$(GPS_GET 2>/dev/null)
    if [ $? -eq 0 ] && [ -n "$GPS_OUTPUT" ]; then
        # Try to extract device path from GPS_GET output
        # Common patterns: /dev/ttyUSB0, /dev/ttyACM0, etc.
        GPS_DEVICE=$(echo "$GPS_OUTPUT" | grep -oP '/dev/tty[A-Z]+[0-9]+' | head -n 1)
        
        if [ -n "$GPS_DEVICE" ] && [ -e "$GPS_DEVICE" ]; then
            LOG green "GPS: Device found at $GPS_DEVICE"
            GPS_ENABLED=true
        else
            LOG yellow "GPS: GPS_GET found but no device path detected"
            GPS_ENABLED=false
        fi
    else
        LOG yellow "GPS: GPS_GET command failed"
        GPS_ENABLED=false
    fi
else
    # Fallback: manually check for GPS devices
    if [ -e /dev/ttyUSB0 ]; then
        GPS_DEVICE="/dev/ttyUSB0"
        LOG green "GPS: Device found at $GPS_DEVICE"
        GPS_ENABLED=true
    elif [ -e /dev/ttyACM0 ]; then
        GPS_DEVICE="/dev/ttyACM0"
        LOG green "GPS: Device found at $GPS_DEVICE"
        GPS_ENABLED=true
    else
        LOG yellow "GPS: No GPS hardware detected"
        GPS_ENABLED=false
    fi
fi

# 3. MODE SELECTION
LED Y SOLID
LOG blue "COUNTER SNOOP v14.2.1 (FIXED)"
LOG "RIGHT: AUTO MODE"
LOG "LEFT:  CONFIG MODE"

BUTTON=$(WAIT_FOR_INPUT)

case "$BUTTON" in
    "RIGHT"|"ENTER")
        LOG green "Starting AUTO MODE..."
        SCENARIO=1
        THRESHOLD=$WALK_THRESHOLD
        LED G SOLID
        sleep 1
        ;;
        
    "LEFT"|"BACK")
        LED C SOLID
        LOG yellow "Check Terminal for Input"
        
        echo -n "Enter RSSI Limit (default -80): "
        read -r input_rssi
        if [ -n "$input_rssi" ] && [ "$input_rssi" -eq "$input_rssi" ] 2>/dev/null; then 
            RSSI_LIMIT=$input_rssi
        fi
        
        echo -n "Enter Threshold (default 3): "
        read -r input_thresh
        if [ -n "$input_thresh" ] && [ "$input_thresh" -eq "$input_thresh" ] 2>/dev/null; then 
            THRESHOLD=$input_thresh
        fi
        
        echo -n "Enable MAC Aging? (y/n, default y): "
        read -r input_aging
        if [[ "$input_aging" =~ ^[Nn] ]]; then
            MAC_AGING_ENABLED=false
        fi
        
        if [ "$MAC_AGING_ENABLED" = true ]; then
            echo -n "MAC Aging Timeout (seconds, default 300): "
            read -r input_timeout
            if [ -n "$input_timeout" ] && [ "$input_timeout" -eq "$input_timeout" ] 2>/dev/null; then 
                MAC_AGING_TIMEOUT=$input_timeout
            fi
        fi
        
        LOG green "Settings Updated: RSSI=$RSSI_LIMIT, Threshold=$THRESHOLD, Aging=$MAC_AGING_ENABLED"
        sleep 1
        LED G SOLID
        ;;
        
    *)
        LOG red "Invalid Input. Auto Mode."
        SCENARIO=1
        THRESHOLD=$WALK_THRESHOLD
        sleep 1
        ;;
esac

# ==========================================
#           MAIN LOOP
# ==========================================

# Load Whitelist
declare -A WHITELIST_MAP
WHITELIST_COUNT=0

if [ -f "$WHITELIST_FILE" ]; then
    LOG blue "Loading Whitelist from: $WHITELIST_FILE"
    while IFS= read -r w_mac || [ -n "$w_mac" ]; do
        CLEAN_MAC=$(echo "$w_mac" | tr -d ' \t\r\n' | tr '[:lower:]' '[:upper:]')
        [ -z "$CLEAN_MAC" ] && continue
        [[ "$CLEAN_MAC" =~ ^#.* ]] && continue
        
        NORMALIZED_MAC=$(normalize_mac "$CLEAN_MAC")
        
        if [ -n "$NORMALIZED_MAC" ]; then
            WHITELIST_MAP["$NORMALIZED_MAC"]=1
            WHITELIST_COUNT=$((WHITELIST_COUNT + 1))
        fi
    done < "$WHITELIST_FILE"
    LOG green "Loaded $WHITELIST_COUNT whitelisted MAC addresses"
else
    LOG yellow "No whitelist.txt found at: $WHITELIST_FILE"
fi

# Init Maps & Time
declare -A MAP_COUNT
declare -A MAP_NAME
declare -A MAP_ALERTED
declare -A MAP_FIRST_SEEN
declare -A MAP_LAST_SEEN
declare -A MAP_RSSI_AVG
declare -A MAP_RSSI_SAMPLES
declare -A MAP_THREAT_PROFILE
declare -A MAP_PROBE_COUNT
declare -A MAP_BEACON_COUNT

LAST_STATUS_TIME=0
LAST_AGING_TIME=0
AGING_INTERVAL=60  # Check for aged MACs every 60 seconds

# Start background processes
start_hopper
scan_bt_background
gps_logger
statistics_exporter
LED B SLOW

LOG blue "🔍 Scanning Active... (RSSI: $RSSI_LIMIT, Threshold: $THRESHOLD, Aging: ${MAC_AGING_TIMEOUT}s)"
LOG yellow "Payload will run until you press a button to stop"
export RSSI_LIMIT

# MAIN LOOP - RUNS FOREVER UNTIL USER STOPS IT (no timeout)
while true; do
    > "$COMBINED"
    
    # 1. WiFi Scan
    timeout 4 tcpdump -i "$IFACE_MONITOR" -e -n -s 256 -l "type mgt subtype probe-req or type mgt subtype beacon" 2>/dev/null | \
    awk -v limit="${RSSI_LIMIT:--80}" '
        {
            rssi="N/A"
            if (match($0, /-[0-9]+dB/, m)) {
                rssi_str = substr(m[0], 1, length(m[0])-2)
                rssi_val = rssi_str + 0
                rssi = rssi_str
                if (rssi_val < limit) next
            }
            
            mac=""; packet_type=""
            for(i=1; i<=NF; i++) {
                if($i ~ /SA:([0-9a-fA-F]{2}:){5}/) { 
                    mac=substr($i, 4); 
                    sub(/,$/, "", mac)
                }
            }
            
            if (mac != "") {
                ssid="<HIDDEN>"; type="[CLI]"
                
                if (index($0, "Beacon (") > 0) { 
                    type="[AP]"
                    packet_type="BEACON"
                    split($0, a, "Beacon \\("); 
                    split(a[2], b, "\\)"); 
                    ssid=b[1]
                    if (ssid == "") ssid="<HIDDEN>"
                }
                else if (index($0, "Request (") > 0) { 
                    packet_type="PROBE"
                    split($0, a, "Request \\("); 
                    split(a[2], b, "\\)"); 
                    ssid=b[1]
                    if (ssid == "") ssid="<HIDDEN>"
                }
                
                print mac " " ssid " " type " " rssi " " packet_type
            }
        }
    ' | sort -u > "$SCAN_WIFI"
    
    # 2. Merge Data
    cat "$SCAN_WIFI" >> "$COMBINED" 2>/dev/null || true
    if [ -f "$SCAN_BT" ]; then cat "$SCAN_BT" >> "$COMBINED" 2>/dev/null || true; fi

    # 3. Analyze
    CURRENT_SCAN_TIME=$(date +%s)
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        
        RAW_MAC=$(echo "$line" | awk '{print $1}')
        RSSI=$(echo "$line" | awk '{print $4}')
        PACKET_TYPE=$(echo "$line" | awk '{print $5}')
        DESC=$(echo "$line" | awk '{$1=""; $4=""; $5=""; print $0}' | sed 's/^[ \t]*//')
        
        # Normalize MAC address
        MAC=$(normalize_mac "$RAW_MAC")
        
        # Skip invalid or empty MACs
        [ -z "$MAC" ] && continue
        
        # Skip Whitelisted
        if [ "${WHITELIST_MAP[$MAC]}" = "1" ]; then 
            continue
        fi
        
        # Determine type from description
        TYPE=$(echo "$DESC" | grep -oP '\[(AP|CLI|BT)\]' || echo "[CLI]")
        
        # Track packet types
        if [ "$PACKET_TYPE" = "PROBE" ]; then
            MAP_PROBE_COUNT["$MAC"]=$((${MAP_PROBE_COUNT[$MAC]:-0} + 1))
        elif [ "$PACKET_TYPE" = "BEACON" ]; then
            MAP_BEACON_COUNT["$MAC"]=$((${MAP_BEACON_COUNT[$MAC]:-0} + 1))
        fi
        
        # Track first and last seen times
        if [ -z "${MAP_FIRST_SEEN[$MAC]}" ]; then
            MAP_FIRST_SEEN[$MAC]=$CURRENT_SCAN_TIME
        fi
        MAP_LAST_SEEN[$MAC]=$CURRENT_SCAN_TIME
        
        # Update RSSI average
        if [ "$RSSI" != "N/A" ]; then
            update_rssi_avg "$MAC" "$RSSI"
        fi
        
        # Track
        if [ -n "${MAP_COUNT[$MAC]}" ]; then
            CURRENT_COUNT=$((MAP_COUNT[$MAC] + 1))
            MAP_COUNT[$MAC]=$CURRENT_COUNT
            
            # Update name if we get better info
            if [[ "${MAP_NAME[$MAC]}" == *"<HIDDEN"* ]] && [[ "$DESC" != *"<HIDDEN"* ]]; then
                 MAP_NAME[$MAC]="$DESC"
            fi
            
            # Analyze threat profile periodically
            if [ "$((CURRENT_COUNT % 3))" -eq 0 ]; then
                analyze_threat_profile "$MAC" "$DESC" "$TYPE"
            fi
            
            # Threat Check
            if [ "$CURRENT_COUNT" -ge "${THRESHOLD:-3}" ] && [ "${MAP_ALERTED[$MAC]}" != "1" ]; then
                TS=$(date '+%H:%M:%S')
                DURATION=$((CURRENT_SCAN_TIME - MAP_FIRST_SEEN[$MAC]))
                PROFILE="${MAP_THREAT_PROFILE[$MAC]:-UNKNOWN}"
                
                echo "$TS [THREAT] ${MAP_NAME[$MAC]} ($MAC) - Profile: $PROFILE - Seen $CURRENT_COUNT times over ${DURATION}s" >> "$LOG_FILE"
                alert_threat "$MAC"
                LOG red "⚠️  THREAT: ${MAP_NAME[$MAC]} ($MAC) - Profile: $PROFILE"
                MAP_ALERTED[$MAC]="1"
            fi
        else
            MAP_COUNT[$MAC]=1
            MAP_NAME[$MAC]="$DESC"
            MAP_ALERTED[$MAC]=0
            
            # Initial threat profile analysis
            analyze_threat_profile "$MAC" "$DESC" "$TYPE"
            
            if [[ "$DESC" != *"<HIDDEN"* ]]; then
                LOG yellow "New: $DESC ($MAC)"
            fi
        fi
    done < "$COMBINED"
    
    # MAC Aging Check
    CURRENT_TIME=$(date +%s)
    if [ "$MAC_AGING_ENABLED" = true ] && [ "$((CURRENT_TIME - LAST_AGING_TIME))" -ge "$AGING_INTERVAL" ]; then
        age_macs
        LAST_AGING_TIME=$CURRENT_TIME
    fi
    
    # Heartbeat Status
    LAST_TIME=${LAST_STATUS_TIME:-0}
    INTERVAL=${STATUS_INTERVAL:-60}
    
    DIFF=$((CURRENT_TIME - LAST_TIME))
    
    if [ "$DIFF" -ge "$INTERVAL" ]; then
        COUNT=${#MAP_COUNT[@]}
        ALERTED_COUNT=0
        for mac in "${!MAP_ALERTED[@]}"; do
            [ "${MAP_ALERTED[$mac]}" = "1" ] && ALERTED_COUNT=$((ALERTED_COUNT + 1))
        done
        
        LOG green "📡 Active: $COUNT devices | Threats: $ALERTED_COUNT | Whitelisted: $WHITELIST_COUNT"
        LAST_STATUS_TIME=$CURRENT_TIME
    fi
    
    sleep 0.5
done