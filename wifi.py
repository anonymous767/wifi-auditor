import subprocess
import os
import time

# ==========================================
# 1. CONFIGURATION & DIRECTORIES
# ==========================================
AUDIT_DIR = os.path.expanduser("~/wifi_audits")
if not os.path.exists(AUDIT_DIR):
    os.makedirs(AUDIT_DIR)

# ==========================================
# 2. MAIN MENU (THE ENGINE)
# ==========================================
# We put this first so you can see the "Logic" of the tool immediately.
def main():
    """The central hub that connects the user to the functions."""
    while True:
        os.system('clear')
        print("="*50)
        print("           WIFI AUDITOR v1.0           ")
        print("="*50)
        
        # This calls the 'Dashboard' function below
        check_status()
        
        print("1. [PREP] Enable Audit Mode")
        print("2. [SCAN] Find Nearby Networks (Step 2)")
        print("3. [DATA] View Stored Files & Logs")
        print("4. [HELP] Knowledge Base")
        print("5. [EXIT] Stop & Return to Internet")
        print("6  [    ]              ")
        
        choice = input("\nSelect an option (1-6): ")
        
        if choice == '1':
            start_audit()
        elif choice == '2':
            print("\n[!] Scanner module coming next!")
            time.sleep(2)
        elif choice == '3':
            view_storage()
        elif choice == '4':
            help_book()
        elif choice == '5':
            stop_audit()
            print("Exiting tool. Stay safe!")
            break

# ==========================================
# 3. WORKING CODE (BEHIND THE SCENES)
# ==========================================

def check_status():
    """Reads terminal output to see if Monitor Mode is on."""
    print("\n" + "-"*45)
    try:
        status = subprocess.check_output("iwconfig", shell=True, stderr=subprocess.STDOUT).decode()
        if "Mode:Monitor" in status:
            print(">> STATUS: [ MONITOR MODE ACTIVE ]")
            print(">> NEXT: Use Option 2 to Scan.")
        else:
            print(">> STATUS: [ MANAGED MODE ]")
            print(">> NEXT: Use Option 1 to Prep.")
    except:
        print(">> STATUS: [ ERROR: NO WIFI CARD ]")
    print("-"*45)

def start_audit():
    """Sends commands to Kali to change WiFi card settings."""
    interface = input("\nEnter your interface (usually wlan0): ")
    subprocess.run("sudo airmon-ng check kill", shell=True)
    subprocess.run(f"sudo airmon-ng start {interface}", shell=True)
    time.sleep(2)
    print("[!] Done. Audit Mode Enabled.")
    input("Press Enter...")

def stop_audit():
    """Restores the system back to normal internet mode."""
    interface = input("\nEnter monitor interface (usually wlan0mon): ")
    subprocess.run(f"sudo airmon-ng stop {interface}", shell=True)
    subprocess.run("sudo systemctl restart NetworkManager", shell=True)
    print("[!] Internet Restored.")
    time.sleep(2)

def view_storage():
    """Lists files inside the ~/wifi_audits folder."""
    os.system('clear')
    print(f"--- STORAGE: {AUDIT_DIR} ---")
    files = os.listdir(AUDIT_DIR)
    for i, file in enumerate(files, 1):
        print(f" {i}. {file}")
    input("\nPress Enter to return...")

def help_book():
    """A quick educational guide for the user."""
    os.system('clear')
    print("--- KNOWLEDGE BASE ---")
    print("Audit Mode: Lets you listen to all WiFi traffic.")
    print("Scanning: Finds names (SSIDs) of nearby routers.")
    input("\nPress Enter to return...")

# ==========================================
# 4. THE STARTER
# ==========================================
if __name__ == "__main__":
    main()