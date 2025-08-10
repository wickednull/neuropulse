#!/usr/bin/env python3
"""
──────────────────────────────────────────────────────────────────────
🧠 NeuroWatch v3.0 – Defensive, Forensic & Auditing Dashboard
Created by Null_Lyfe | Evolved with AI Assistance

This toolkit is designed for ethical security research, network analysis,
and defensive auditing. Use responsibly and only on networks you are
authorized to test.
──────────────────────────────────────────────────────────────────────
"""

# ──────────────────── Core Imports ────────────────────
import os, subprocess, threading, time, json, shutil, signal, sys, re, socket
from datetime import datetime
from tkinter import *
from tkinter import ttk, filedialog, messagebox, simpledialog, scrolledtext
import psutil
import platform

# Attempt to import Scapy, a key dependency for new features
try:
    from scapy.all import sniff, ARP, DNSQR, Raw
except ImportError:
    print("[FATAL] Scapy is not installed. Please run 'pip install scapy'.")
    sys.exit(1)

# ──────────────────── Configuration Engine ────────────────────
CONFIG = {}
CONFIG_PATH = "neuropulse_config.json"

def load_or_create_config():
    """Loads configuration from JSON or creates a default one."""
    global CONFIG
    default_config = {
        "default_interface": "wlan0",
        "default_monitor_interface": "wlan0mon",
        "shodan_api_key": "YOUR_API_KEY_HERE",
        "log_directory": "neuropulse_logs"
    }
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r") as f:
                CONFIG = json.load(f)
            for key, value in default_config.items():
                CONFIG.setdefault(key, value)
        except json.JSONDecodeError:
            print(f"[WARNING] {CONFIG_PATH} is corrupted. Recreating with defaults.")
            CONFIG = default_config
    else:
        print("[INFO] No config file found. Creating default 'neuropulse_config.json'.")
        CONFIG = default_config
    
    with open(CONFIG_PATH, "w") as f:
        json.dump(CONFIG, f, indent=4)

# ──────────────────── Logging Engine ────────────────────
def setup_logging():
    global LOG_DIR
    LOG_DIR = CONFIG.get("log_directory", "neuropulse_logs")
    os.makedirs(LOG_DIR, exist_ok=True)

def log_message(widget, msg):
    """Prints a message to a specific GUI widget and the session log."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{now}] {msg}"
    
    # Insert into GUI widget
    widget.insert(END, line + "\n")
    widget.see(END)
    
    # Write to master log file
    try:
        with open(os.path.join(LOG_DIR, "session.log"), "a", encoding='utf-8') as f:
            f.write(line + "\n")
    except Exception as e:
        print(f"FATAL: Could not write to log file: {e}")

# ──────────────────── Global State & Process Management ────────────────────
ACTIVE_PROCESSES = {}
process_treeview = None
stop_sniffing_event = threading.Event()
arp_cache = {}

def register_process(p, cmd_str):
    if p:
        pid = p.pid
        ACTIVE_PROCESSES[pid] = {"cmd": cmd_str, "process": p}
        if process_treeview:
            process_treeview.insert("", "end", iid=pid, values=(pid, cmd_str))

def kill_selected_process():
    selected_items = process_treeview.selection()
    if not selected_items: return
    pid_to_kill = int(selected_items[0])
    if pid_to_kill in ACTIVE_PROCESSES:
        try:
            proc = ACTIVE_PROCESSES[pid_to_kill]["process"]
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            proc.terminate()
            time.sleep(1)
            if proc.poll() is None: proc.kill()
            del ACTIVE_PROCESSES[pid_to_kill]
            process_treeview.delete(selected_items[0])
        except Exception as e:
            messagebox.showerror("Error", f"Failed to kill process {pid_to_kill}: {e}")


# ──────────────────── Generic Tool Runner ────────────────────
def run_tool_in_thread(widget, command, tool_name):
    """Runs a command-line tool in a separate thread and pipes output to a GUI widget."""
    log_message(widget, f"Starting {tool_name}...")
    
    def task():
        try:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, universal_newlines=True)
            register_process(process, " ".join(command))
            for line in iter(process.stdout.readline, ''):
                widget.insert(END, line)
                widget.see(END)
            process.stdout.close()
            process.wait()
            log_message(widget, f"{tool_name} finished.")
        except FileNotFoundError:
            log_message(widget, f"[ERROR] {tool_name} command not found. Is it installed and in your PATH?")
        except Exception as e:
            log_message(widget, f"[ERROR] An error occurred with {tool_name}: {e}")

    threading.Thread(target=task, daemon=True).start()

# ──────────────────── Reconnaissance Tools ────────────────────
def run_nmap_recon(widget, target):
    if not target: messagebox.showwarning("Input Error", "Please provide a target IP or domain."); return
    command = ["nmap", "-sV", "-A", "-O", target]
    run_tool_in_thread(widget, command, "Nmap Scan")

def run_theharvester(widget, domain):
    if not domain: messagebox.showwarning("Input Error", "Please provide a target domain."); return
    log_file = os.path.join(LOG_DIR, f"theHarvester_{domain}.html")
    command = ["theHarvester", "-d", domain, "-b", "all", "-f", log_file]
    run_tool_in_thread(widget, command, "theHarvester")

def run_sublist3r(widget, domain):
    if not domain: messagebox.showwarning("Input Error", "Please provide a target domain."); return
    log_file = os.path.join(LOG_DIR, f"sublist3r_{domain}.txt")
    command = ["sublist3r", "-d", domain, "-o", log_file]
    run_tool_in_thread(widget, command, "Sublist3r")

def run_whatweb(widget, url):
    if not url: messagebox.showwarning("Input Error", "Please provide a target URL (e.g., http://example.com)."); return
    command = ["whatweb", "-v", url]
    run_tool_in_thread(widget, command, "WhatWeb")

# ──────────────────── Network Forensics Engine (Scapy) ────────────────────
def arp_watcher_callback(arp_tree, pkt):
    if pkt.haslayer(ARP) and pkt[ARP].op in (1, 2): # who-has or is-at
        ip_addr = pkt[ARP].psrc
        mac_addr = pkt[ARP].hwsrc
        if ip_addr not in arp_cache:
            arp_cache[ip_addr] = mac_addr
            arp_tree.insert("", "end", values=(ip_addr, mac_addr, "First Seen", datetime.now().strftime("%H:%M:%S")))
            arp_tree.yview_moveto(1)
        elif arp_cache[ip_addr] != mac_addr:
            arp_tree.insert("", "end", values=(ip_addr, mac_addr, f"CONFLICT! (was {arp_cache[ip_addr]})", datetime.now().strftime("%H:%M:%S")), tags=('conflict',))
            arp_cache[ip_addr] = mac_addr # Update to new MAC
            arp_tree.yview_moveto(1)

def dns_monitor_callback(dns_tree, pkt):
    if pkt.haslayer(DNSQR):
        query = pkt[DNSQR].qname.decode()
        dns_tree.insert("", "end", values=(datetime.now().strftime("%H:%M:%S"), pkt.getlayer(ARP).psrc if pkt.haslayer(ARP) else 'N/A', query))
        dns_tree.yview_moveto(1)

def forensics_sniffer_thread(iface, arp_tree, dns_tree):
    log_message(arp_tree, f"Starting live forensics sniffer on {iface}...")
    
    def packet_handler(pkt):
        arp_watcher_callback(arp_tree, pkt)
        dns_monitor_callback(dns_tree, pkt)
    
    sniff(iface=iface, prn=packet_handler, store=0, stop_filter=lambda x: stop_sniffing_event.is_set())
    
    # This part will be reached when the sniffing stops
    arp_tree.insert(END, "Sniffer stopped.\n")

def start_forensics_sniffer(iface, arp_tree, dns_tree):
    if not iface: messagebox.showwarning("Input Error", "Please select an interface."); return
    stop_sniffing_event.clear()
    arp_cache.clear()
    # Clear Treeviews
    for i in arp_tree.get_children(): arp_tree.delete(i)
    for i in dns_tree.get_children(): dns_tree.delete(i)
    
    threading.Thread(target=forensics_sniffer_thread, args=(iface, arp_tree, dns_tree), daemon=True).start()

def stop_forensics_sniffer():
    stop_sniffing_event.set()

# ──────────────────── Auditing & Hardening Tools ────────────────────
def audit_wifi_security(widget):
    log_message(widget, "Starting Wi-Fi security audit...")
    iface = CONFIG.get("default_monitor_interface", "wlan0mon")
    
    def task():
        # A simple placeholder using nmcli, can be replaced with airodump-ng parsing
        try:
            log_message(widget, "Using nmcli for Wi-Fi scan...")
            process = subprocess.run(["nmcli", "-f", "SSID,SECURITY,SIGNAL", "dev", "wifi"], capture_output=True, text=True, check=True)
            log_message(widget, "--- Wi-Fi Security Audit Results ---")
            for line in process.stdout.strip().splitlines()[1:]: # Skip header
                parts = line.split()
                ssid = parts[0]
                security = " ".join(parts[1:-1])
                signal = parts[-1]
                
                grade = "UNKNOWN"
                if "WPA3" in security: grade = "EXCELLENT"
                elif "WPA2" in security: grade = "GOOD"
                elif "WPA1" in security: grade = "POOR"
                elif "WEP" in security: grade = "CRITICAL"
                elif not security or security == "--": grade = "NONE (Open)"
                
                log_message(widget, f"SSID: {ssid:<20} | Security: {security:<15} | Grade: {grade:<10} | Signal: {signal}")
        except Exception as e:
            log_message(widget, f"[ERROR] Could not run Wi-Fi audit. Ensure 'nmcli' is installed or modify script to use airodump-ng. Error: {e}")
            
    threading.Thread(target=task, daemon=True).start()

def audit_ssh_config(widget):
    log_message(widget, "Auditing SSH server configuration (/etc/ssh/sshd_config)...")
    path = "/etc/ssh/sshd_config"
    recommendations = {
        "PermitRootLogin": "no",
        "PasswordAuthentication": "no",
        "X11Forwarding": "no",
        "PermitEmptyPasswords": "no",
        "Protocol": "2"
    }
    try:
        with open(path, "r") as f:
            config = f.read()
        log_message(widget, "--- SSHd Hardening Report ---")
        for key, value in recommendations.items():
            if re.search(f"^{key}\s+{value}", config, re.MULTILINE):
                log_message(widget, f"[✓] Good: '{key}' is set to '{value}'.")
            else:
                log_message(widget, f"[!] WARNING: '{key}' is not set to '{value}'. Check your configuration.")
    except FileNotFoundError:
        log_message(widget, f"[ERROR] {path} not found.")
    except Exception as e:
        log_message(widget, f"[ERROR] Could not read SSH config: {e}")

def analyze_firewall_rules(widget):
    log_message(widget, "Analyzing iptables firewall rules...")
    run_tool_in_thread(widget, ["iptables", "-L", "-n", "-v"], "iptables")

# ──────────────────── GUI Builder ────────────────────
def build_gui():
    root = Tk()
    root.title("🧠 NeuroPulse v3.0 – Defensive & Forensic Dashboard")
    root.configure(bg="#111111")
    root.geometry("1400x900")

    style = ttk.Style()
    style.configure("TNotebook", background="#111", borderwidth=0)
    style.configure("TNotebook.Tab", background="#333", foreground="#FFF", padding=[10, 5], font=("Consolas", 10))
    style.map("TNotebook.Tab", background=[("selected", "#00FFAA")], foreground=[("selected", "#111")])
    notebook = ttk.Notebook(root, style="TNotebook")
    notebook.pack(pady=10, padx=10, fill="both", expand=True)

    # --- Reconnaissance Tab ---
    recon_tab = Frame(notebook, bg="#1E1E1E")
    notebook.add(recon_tab, text="🌐 Reconnaissance")
    
    recon_controls = Frame(recon_tab, bg="#1E1E1E")
    recon_controls.pack(fill=X, padx=5, pady=5)
    Label(recon_controls, text="Target Domain/IP/URL:", bg="#1E1E1E", fg="#00FFAA").pack(side=LEFT, padx=5)
    recon_target_entry = Entry(recon_controls, width=40, bg="#333", fg="white", insertbackground="white")
    recon_target_entry.pack(side=LEFT, fill=X, expand=True, padx=5)

    recon_buttons = Frame(recon_tab, bg="#1E1E1E")
    recon_buttons.pack(fill=X, padx=5, pady=5)
    Button(recon_buttons, text="Nmap Scan", command=lambda: run_nmap_recon(recon_output, recon_target_entry.get())).pack(side=LEFT, padx=5)
    Button(recon_buttons, text="theHarvester", command=lambda: run_theharvester(recon_output, recon_target_entry.get())).pack(side=LEFT, padx=5)
    Button(recon_buttons, text="Sublist3r", command=lambda: run_sublist3r(recon_output, recon_target_entry.get())).pack(side=LEFT, padx=5)
    Button(recon_buttons, text="WhatWeb", command=lambda: run_whatweb(recon_output, recon_target_entry.get())).pack(side=LEFT, padx=5)

    recon_output = scrolledtext.ScrolledText(recon_tab, bg="black", fg="#00FF88", font=("Consolas", 10))
    recon_output.pack(fill="both", expand=True, padx=5, pady=5)

    # --- Live Forensics Tab ---
    forensics_tab = Frame(notebook, bg="#1E1E1E")
    notebook.add(forensics_tab, text="🔬 Live Forensics")
    
    forensics_controls = Frame(forensics_tab, bg="#1E1E1E")
    forensics_controls.pack(fill=X, padx=5, pady=5)
    Label(forensics_controls, text="Sniffing Interface:", bg="#1E1E1E", fg="#00FFAA").pack(side=LEFT, padx=5)
    iface_var = StringVar(value=CONFIG.get("default_interface"))
    iface_entry = Entry(forensics_controls, textvariable=iface_var, width=15)
    iface_entry.pack(side=LEFT, padx=5)
    
    forensics_pane = PanedWindow(forensics_tab, orient=VERTICAL, sashrelief=RAISED, bg="#1E1E1E")
    forensics_pane.pack(fill="both", expand=True)

    arp_frame = LabelFrame(forensics_pane, text="Live ARP Watcher", bg="#1E1E1E", fg="#00FFAA")
    arp_tree = ttk.Treeview(arp_frame, columns=("ip", "mac", "status", "time"), show="headings")
    arp_tree.heading("ip", text="IP Address"); arp_tree.heading("mac", text="MAC Address"); arp_tree.heading("status", text="Status"); arp_tree.heading("time", text="Time Seen")
    arp_tree.column("ip", width=150); arp_tree.column("mac", width=150); arp_tree.column("status", width=200); arp_tree.column("time", width=100)
    arp_tree.pack(fill="both", expand=True)
    arp_tree.tag_configure('conflict', background='red', foreground='white')
    forensics_pane.add(arp_frame)

    dns_frame = LabelFrame(forensics_pane, text="Live DNS Query Monitor", bg="#1E1E1E", fg="#00FFAA")
    dns_tree = ttk.Treeview(dns_frame, columns=("time", "source", "query"), show="headings")
    dns_tree.heading("time", text="Timestamp"); dns_tree.heading("source", text="Source IP"); dns_tree.heading("query", text="Queried Domain")
    dns_tree.column("time", width=100); dns_tree.column("source", width=150);
    dns_tree.pack(fill="both", expand=True)
    forensics_pane.add(dns_frame)

    Button(forensics_controls, text="Start Sniffer", command=lambda: start_forensics_sniffer(iface_var.get(), arp_tree, dns_tree)).pack(side=LEFT, padx=5)
    Button(forensics_controls, text="Stop Sniffer", command=stop_forensics_sniffer).pack(side=LEFT, padx=5)
    
    # --- Auditing Tab ---
    auditing_tab = Frame(notebook, bg="#1E1E1E")
    notebook.add(auditing_tab, text="🛡️ Auditing & Hardening")
    
    audit_buttons = Frame(auditing_tab, bg="#1E1E1E")
    audit_buttons.pack(fill=X, padx=5, pady=5)
    Button(audit_buttons, text="Audit Wi-Fi Security", command=lambda: audit_wifi_security(audit_output)).pack(side=LEFT, padx=5)
    Button(audit_buttons, text="Audit SSH Config", command=lambda: audit_ssh_config(audit_output)).pack(side=LEFT, padx=5)
    Button(audit_buttons, text="Analyze Firewall Rules", command=lambda: analyze_firewall_rules(audit_output)).pack(side=LEFT, padx=5)

    audit_output = scrolledtext.ScrolledText(auditing_tab, bg="black", fg="#00FF88", font=("Consolas", 10))
    audit_output.pack(fill="both", expand=True, padx=5, pady=5)

    # --- Process Manager Tab ---
    proc_tab = Frame(notebook, bg="#1E1E1E")
    notebook.add(proc_tab, text="⚙️ Process Manager")
    
    global process_treeview
    proc_frame = LabelFrame(proc_tab, text="Active Processes", bg="#1E1E1E", fg="#00FFAA")
    proc_frame.pack(fill="both", expand=True, padx=10, pady=10)
    cols = ("PID", "Command"); process_treeview = ttk.Treeview(proc_frame, columns=cols, show="headings")
    for col in cols: process_treeview.heading(col, text=col)
    process_treeview.column("PID", width=100, anchor=CENTER); process_treeview.pack(side=LEFT, fill="both", expand=True)
    Button(proc_frame, text="KILL SELECTED", command=kill_selected_process, bg="#FF4444", fg="#FFFFFF").pack(side=RIGHT, padx=10, pady=10, anchor=N)

    root.mainloop()

# ──────────────────── Script Entry Point ────────────────────
if __name__ == '__main__':
    if platform.system() != "Windows" and os.geteuid() != 0:
        messagebox.showerror("Root Required", "This toolkit requires root privileges for network operations. Please run with sudo.")
        sys.exit(1)
    
    load_or_create_config()
    setup_logging()
    build_gui()

