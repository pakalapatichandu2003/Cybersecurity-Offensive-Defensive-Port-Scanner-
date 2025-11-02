import socket, threading, subprocess, platform, whois
import ttkbootstrap as tb
from ttkbootstrap.constants import *
from tkinter import Text, messagebox, END
import tkinter.messagebox as messagebox
from tkinter import filedialog

import tkinter as tk  # Needed for tk.END reference
import webbrowser
import os
import pathlib


# ----------------- Utility functions -----------------

def show_ethics_warning():
    """Show a modal with ethical/legal warning. User must accept to continue."""
    win = tb.Toplevel(app)
    win.title("Important: Use Ethically")
    win.geometry("620x320")
    win.transient(app)
    win.grab_set()

    text = (
        "Port scanning can be intrusive and may be illegal or against terms of service "
        "if performed without explicit authorization. Only scan systems you own or have "
        "written permission to test. The author and this tool are not responsible for "
        "any misuse.\n\nBy clicking 'I AGREE' you confirm that you will only use PortXScanner "
        "for authorized, legal, and ethical testing."
    )

    tb.Label(win, text="Ethical & Legal Notice", font=("Segoe UI", 12, "bold")).pack(anchor="w", padx=12, pady=(12,4))
    txt = Text(win, wrap="word", height=10, bg="#1e1e1e", fg="#fff")
    txt.pack(fill="both", expand=True, padx=12, pady=(0,6))
    txt.insert(END, text)
    txt.configure(state="disabled")

    def accept():
        win.destroy()

    def decline():
        win.destroy()
        app.destroy()

    btn_frame = tb.Frame(win)
    btn_frame.pack(fill="x", padx=12, pady=8)
    tb.Button(btn_frame, text="I AGREE", bootstyle="success", command=accept).pack(side="right")
    tb.Button(btn_frame, text="DECLINE", bootstyle="danger", command=decline).pack(side="right", padx=(0,8))


# If you already have HTML content from the earlier message, paste it here.
# I included the descriptive HTML used earlier as HTML_CONTENT.
HTML_CONTENT = r"""<!DOCTYPE html>
<html lang="en" data-bs-theme="light">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>PortXScanner - Project Information</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" />
  <style>
    body { font-family: 'Segoe UI', sans-serif; margin: 0; background: #f4f6f8; }
    .container { padding: 2rem; max-width: 900px; }
    blockquote { border-left: 5px solid #28a745; padding-left: 1rem; background-color: #f8f9fa; }
    h1, h3, h4 { color: #198754; }
    ul li { margin-bottom: 0.5rem; }
    footer { margin-top: 3rem; text-align: center; font-size: 0.9rem; color: #777; }
  </style>
</head>
<body>
  <div class="container">
    <h1>🛡️ PortXScanner</h1>
    <blockquote class="blockquote">
      Developed by <b>Pakalapati Chandu</b> as part of a <b>Cyber Security Internship Project</b>.
    </blockquote>

    <h3>🔍 Project Overview</h3>
    <p>
      <b>PortXScanner</b> is a graphical cybersecurity tool designed for network reconnaissance and vulnerability assessment.
      It combines traditional <b>socket-level scanning</b> with advanced <b>Nmap integrations</b>, allowing both beginner
      and advanced users to efficiently analyze hosts, ports, and services in a user-friendly GUI environment.
    </p>

    <h4>⚙️ Key Features</h4>
    <ul>
      <li><b>Port Scanning</b> — Scan a specific target for open TCP/UDP ports using socket connections.</li>
      <li><b>WHOIS Lookup</b> — Retrieve domain registration details and IP information.</li>
      <li><b>Nmap Integration</b> — Run powerful scan profiles (Quick, Aggressive, OS Detection, Version Detection, Ping).</li>
      <li><b>Batch Scanning</b> — Load multiple targets from a text file and perform automated scans with multiple profiles.</li>
      <li><b>Server Information</b> — Fetch and display HTTP headers and server response banners.</li>
      <li><b>TTL & Local IP Detection</b> — Analyze ICMP responses and find your local IP address easily.</li>
      <li><b>Modern GUI</b> — Built with <code>ttkbootstrap</code> for a clean, responsive dark mode interface.</li>
    </ul>

    <h4>💡 Technical Highlights</h4>
    <ul>
      <li>Developed in Python using <b>socket</b>, <b>subprocess</b>, <b>threading</b>, and <b>whois</b> libraries.</li>
      <li>Uses <b>Nmap</b> for advanced scanning operations, integrated through command-line execution.</li>
      <li>Responsive and dynamic GUI powered by <b>ttkbootstrap</b> (Themed Tkinter).</li>
      <li>Supports cross-platform use (Windows/Linux).</li>
    </ul>

    <h4>🎯 Purpose</h4>
    <p>
      The main goal of PortXScanner is to provide an easy-to-use cybersecurity tool for learners and professionals to
      identify open ports, detect services, and gain insights into target systems' network exposure.
      This project bridges practical network security testing with visual reporting.
    </p>

    <h4>🔒 Future Enhancements</h4>
    <ul>
      <li>Export results to PDF/CSV reports.</li>
      <li>Add vulnerability scoring based on service banners.</li>
      <li>Integrate live network graph visualization.</li>
      <li>Implement multi-threaded Nmap scanning for faster results.</li>
    </ul>

    <footer>
      <hr>
      <p>© 2025 PortXScanner by Pakalapati Chandu | Cyber Security Internship Project</p>
    </footer>
  </div>
</body>
</html>
"""

def open_project_info():
    """
    Opens project_info.html in the default browser.
    If the file doesn't exist next to the script, create it automatically using HTML_CONTENT.
    """
    try:
        # directory where the script lives; fallback to cwd if __file__ missing (e.g. in interactive shell)
        base_dir = os.path.dirname(os.path.abspath(__file__))
    except Exception:
        base_dir = os.getcwd()

    html_path = os.path.join(base_dir, "project_info.html")

    # If missing, create the file with the bundled HTML content
    if not os.path.exists(html_path):
        try:
            with open(html_path, "w", encoding="utf-8") as f:
                f.write(HTML_CONTENT)
        except Exception as e:
            messagebox.showerror("File Error", f"Could not create project_info.html:\n{e}")
            return

    # Use pathlib to build a file:// URI that works cross-platform
    try:
        uri = pathlib.Path(html_path).absolute().as_uri()
        webbrowser.open(uri)
    except Exception as e:
        # Last-resort: try webbrowser.open with file:///
        try:
            webbrowser.open(f"file:///{os.path.abspath(html_path)}")
        except Exception as e2:
            messagebox.showerror("Open Error", f"Could not open {html_path}:\n{e}\n{e2}")
            return


# def open_project_info():
#     # Make sure the HTML file is in the same folder
#     html_file = os.path.join(os.getcwd(), "C:\Users\pakal\OneDrive\Desktop\Cyber Security Ptoject\Another Way Project Info\templates")
#     if not os.path.exists(html_file):
#         messagebox.showerror("File Missing", "project_info.html was not found in this folder.")
#         return
#     webbrowser.open(f"file://{html_file}")

# def open_project_info():
#     # Path to your HTML file
#     html_file = r"C:\Users\pakal\OneDrive\Desktop\Cyber Security Project\Another Way Project Info\templates\project_info.html"

#     if not os.path.exists(html_file):
#         messagebox.showerror("File Missing", f"{html_file} was not found.")
#         return

#     webbrowser.open(f"file:///{html_file}")


# 🧰 Utility Functions


def resolve_ip(target):
    try:
        ip = socket.gethostbyname(target)
        label_resolve.config(text=f"Resolved IP: {ip}")
        return ip
    except Exception:
        label_resolve.config(text="Resolved IP: 0.0.0.0")
        return None

def get_service_name(port, proto):
    try:
        return socket.getservbyport(port, proto.lower())
    except OSError:
        return "Unknown"

def grab_banner(ip, port):
    try:
        s = socket.socket()
        s.settimeout(1)
        s.connect((ip, port))
        s.sendall(b"HEAD / HTTP/1.1\r\nHost: example\r\n\r\n")
        data = s.recv(1024).decode(errors="ignore")
        s.close()
        for line in data.splitlines():
            if line.lower().startswith("server:"):
                return line.strip()
        return data.splitlines()[0] if data else "Unknown"
    except:
        return "Unknown"

def scan_port(ip, port, proto, output):
    if proto in ("TCP", "BOTH"):
        s = socket.socket()
        s.settimeout(1)
        if s.connect_ex((ip, port)) == 0:
            service = get_service_name(port, "tcp")
            banner = grab_banner(ip, port)
            output.insert(END, f"{port:<6} {service:<15} TCP  OPEN    {banner}\n", "open")
        s.close()
    if proto in ("UDP", "BOTH"):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1)
        s.sendto(b"", (ip, port))
        try:
            s.recvfrom(1024)
        except socket.timeout:
            service = get_service_name(port, "udp")
            output.insert(END, f"{port:<6} {service:<15} UDP  OPEN|FILT\n", "open")
        s.close()
#Bathch scan
def load_file_action():
    file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
    if file_path:
        with open(file_path, "r") as file:
            lines = [line.strip() for line in file if line.strip()]
            output_batch.delete(1.0, END)
            output_batch.insert(END, "\n".join(lines))
            label_batch_status.config(text=f"Loaded {len(lines)} targets.")

def batch_scan_action():
    targets = output_batch.get(1.0, END).strip().splitlines()
    # ✅ Custom Nmap scan flag mapping
    scan_flags_map = {
        "Quick Scan (-F)": "-F",
         "Aggressive Full Scan": "-A",  # Custom Aggressive Scan
        "OS Detection (-O)": "-O",
        "Version Detection (-sV)": "-sV"
    }

    if not targets:
        messagebox.showwarning("Empty List", "No targets loaded.")
        return

    # ✅ Collect selected scan flags from UI checkboxes
    selected_scans = [scan_flags_map[label] for label, var in scan_options.items() if var.get()]
    if not selected_scans:
        messagebox.showinfo("No Scan Selected", "Select at least one scan profile.")
        return

    output_batch.insert(END, f"\nRunning scans: {' | '.join(selected_scans)}\n", "nmap")
    output_batch.insert(END, "-" * 60 + "\n", "nmap")

    for target in targets:
        ip = resolve_ip(target)
        if not ip:
            output_batch.insert(END, f"{target:<20} -> Could not resolve\n", "error")
            continue

        for flag in selected_scans:
            output_batch.insert(END, f"\n➡ Scanning {target} ({ip}) with flag: {flag}\n", "nmap")
            output_batch.insert(END, "-" * 50 + "\n", "nmap")


            try:
                # ✅ Run Nmap using split flags for correct execution
                result = subprocess.check_output(
                    [get_nmap_path()] + flag.split() + [ip],
                    stderr=subprocess.STDOUT,
                    text=True
                )
                cleaned_result = []
                skip = False
                for line in result.splitlines():
                    if line.strip().startswith("==============NEXT SERVICE FINGERPRINT"):
                        skip = True
                    if not skip:
                        cleaned_result.append(line)
                    elif line.strip() == "":
                        skip = False  # End of fingerprint block
                output_batch.insert(END, "\n".join(cleaned_result) + "\n", "nmap")

            except subprocess.CalledProcessError as e:
                output_batch.insert(END, f"Error scanning {target} [{flag}]: {e.output}\n", "error")
            except FileNotFoundError:
                output_batch.insert(END, "Nmap not found. Please check the path.\n", "error")

# 🖥 Scan Handlers

def port_scan_action():
    target = entry_scan_target.get().strip()
    ip = resolve_ip(target)
    if not ip:
        return

    output_scan.delete(1.0, END)
    output_scan.insert(END, f"{'Port':<6} {'Service':<15} Proto Status   Version/Banner\n")
    output_scan.insert(END, "-" * 70 + "\n")
    start = int(entry_start.get())
    end = int(entry_end.get())
    proto = combo_proto.get()

    for port in range(start, end + 1):
        threading.Thread(target=scan_port, args=(ip, port, proto, output_scan)).start()

def whois_action():
    output_whois.delete(1.0, END)
    domain = entry_whois.get().strip()
    ip = resolve_ip(domain)
    if not ip:
        return

    output_whois.insert(END, f"WHOIS info for {domain}:\n\n")
    try:
        info = whois.whois(domain)
        for k, v in info.items():
            output_whois.insert(END, f"{k}: {v}\n")
    except Exception as e:
        output_whois.insert(END, f"Error: {e}\n")

def run_aggressive_scan():
    target = entry_misc.get().strip()
    ip = resolve_ip(target)
    if not ip:
        output_misc.insert(tk.END, f"Could not resolve IP for {target}\n", "error")
        return

    output_misc.insert(tk.END, f"\nStarting Aggressive Nmap Scan on {target}...\n", "nmap")
    output_misc.insert(tk.END, "-" * 60 + "\n", "nmap")

    try:
        result = subprocess.check_output([get_nmap_path(), '-A', target], stderr=subprocess.STDOUT, text=True)
        output_misc.insert(tk.END, result, "nmap")
        output_misc.insert(tk.END, "\nAggressive scan complete.\n", "nmap")
    except subprocess.CalledProcessError as e:
        output_misc.insert(tk.END, f"Error running aggressive scan: {e.output}\n", "error")
    except FileNotFoundError:
        output_misc.insert(tk.END, "Nmap executable not found. Check installation path.\n", "error")


def ttl_action():
    output_misc.delete(1.0, END)
    domain = entry_misc.get().strip()
    ip = resolve_ip(domain)
    if not ip:
        return
    param = "-n" if platform.system().lower().startswith("win") else "-c"
    try:
        res = subprocess.check_output(["ping", param, "1", domain], text=True)
        for line in res.splitlines():
            if "TTL=" in line or "ttl=" in line.lower():
                output_misc.insert(END, f"{line.strip()}\n")
    except Exception as e:
        output_misc.insert(END, f"Error: {e}\n")

def serverinfo_action():
    output_misc.delete(1.0, END)
    domain = entry_misc.get().strip()
    ip = resolve_ip(domain)
    if not ip:
        return
    try:
        s = socket.create_connection((ip, 80), timeout=3)
        s.sendall(f"HEAD / HTTP/1.1\r\nHost: {domain}\r\nConnection: close\r\n\r\n".encode())
        data = s.recv(2048).decode(errors="ignore")
        s.close()
        output_misc.insert(END, "Server headers:\n")
        for line in data.splitlines():
            output_misc.insert(END, line + "\n")
    except Exception as e:
        output_misc.insert(END, f"Error: {e}\n")

def localip_action():
    output_misc.delete(1.0, END)
    try:
        ip = socket.gethostbyname(socket.gethostname())
        output_misc.insert(END, f"Local IP: {ip}\n")
    except Exception as e:
        output_misc.insert(END, f"Error: {e}\n")

# 🛰 Nmap Aggressive Scan

def run_nmap_profile_scan(target, profile_name):
    output_misc.delete(1.0, END)
    ip = resolve_ip(target)
    if not ip:
        output_misc.insert(END, "Invalid target.\n", "error")
        return

    profile_flags = {
        "Quick Scan (-F)": "-F",
        "Aggressive Scan (-A)": "-A",
        "OS Detection (-O)": "-O",
        "Version Detection (-sV)": "-sV",
        "Ping Scan (-sn)": "-sn",
        #"Custom Full Scan (-p- -sC -sV)": "-p- -sC -sV"
    }

    flags = profile_flags.get(profile_name, "-A")
    output_misc.insert(END, f"Running Nmap scan: nmap {flags} {ip}\n\n", "nmap")

    try:
        result = subprocess.check_output(["nmap"] + flags.split() + [ip], stderr=subprocess.STDOUT, text=True)
        output_misc.insert(END, result, "nmap")
    except subprocess.CalledProcessError as e:
        output_misc.insert(END, f"Error: {e.output}", "error")
def get_nmap_path():
    if platform.system().lower().startswith("win"):
        return r"C:\Program Files (x86)\Nmap\nmap.exe"
    else:
        return "nmap"

def run_nmap_scan(target, profile_name):
    output_misc.delete(1.0, tk.END)
    ip = resolve_ip(target)
    if not ip:
        output_misc.insert(tk.END, "Invalid target.\n")
        return

    flags = {
        "Quick Scan (-F)": "-F",
        "Aggressive Scan (-A)": "-A",
        "OS Detection (-O)": "-O",
        "Version Detection (-sV)": "-sV",
        "Ping Scan (-sn)": "-sn",
        "Custom Full Scan (-p- -sC -sV)": "-p- -sC -sV"
    }.get(profile_name, "-A")

    output_misc.insert(tk.END, f"Running Nmap scan: nmap {flags} {ip}\n\n")
    try:
        result = subprocess.check_output([get_nmap_path()] + flags.split() + [ip], stderr=subprocess.STDOUT, text=True)
        output_misc.insert(tk.END, result)
    except FileNotFoundError:
        output_misc.insert(tk.END, "Nmap not found. Please install or correct path.\n")
    except subprocess.CalledProcessError as e:
        output_misc.insert(tk.END, f"Scan failed:\n{e.output}\n")

# 🏗️ Build UI
app = tb.Window(themename="darkly")
app.title("PortXScanner")
app.geometry("850x650")

# Show ethics warning before user can use the app
show_ethics_warning()


tb.Button(app, text="📄 Project Info Page", bootstyle="info", command=open_project_info).pack(padx=10, pady=5)

label_resolve = tb.Label(app, text="Resolved IP: 0.0.0.0", bootstyle="info")
label_resolve.pack(fill=X, padx=10, pady=5)

tabs = tb.Notebook(app)
tabs.pack(fill=BOTH, expand=True, padx=10, pady=10)

# ---- Port Scan Tab ----
tab_scan = tb.Frame(tabs)
tabs.add(tab_scan, text="🔍 Port Scan")

tb.Label(tab_scan, text="Target:").grid(row=0, column=0, padx=5, pady=5, sticky=E)
entry_scan_target = tb.Entry(tab_scan, width=30); entry_scan_target.grid(row=0, column=1, padx=5, pady=5)
tb.Label(tab_scan, text="Start Port:").grid(row=1, column=0, padx=5, pady=5, sticky=E)
entry_start = tb.Entry(tab_scan, width=10); entry_start.grid(row=1, column=1, sticky=W, padx=5, pady=5)
tb.Label(tab_scan, text="End Port:").grid(row=1, column=2, padx=5, pady=5, sticky=E)
entry_end = tb.Entry(tab_scan, width=10); entry_end.grid(row=1, column=3, sticky=W, padx=5, pady=5)
tb.Label(tab_scan, text="Protocol:").grid(row=2, column=0, padx=5, pady=5, sticky=E)
combo_proto = tb.Combobox(tab_scan, values=["TCP", "UDP", "BOTH"]); combo_proto.set("BOTH")
combo_proto.grid(row=2, column=1, padx=5, pady=5, sticky=W)
tb.Button(tab_scan, text="Start Scan", bootstyle="success", command=port_scan_action).grid(row=2, column=3, padx=5, pady=5)

output_scan = Text(tab_scan, bg="#1e1e1e", fg="#00ffcc", width=90, height=25)
output_scan.grid(row=3, column=0, columnspan=4, padx=10, pady=10)
output_scan.tag_config("open", foreground="cyan", font=("Consolas", 10, "bold"))

# ---- WHOIS Tab ----
tab_whois = tb.Frame(tabs)
tabs.add(tab_whois, text="🌐 WHOIS Lookup")

tb.Label(tab_whois, text="Domain:").grid(row=0, column=0, padx=5, pady=5, sticky=E)
entry_whois = tb.Entry(tab_whois, width=30); entry_whois.grid(row=0, column=1, padx=5, pady=5)
tb.Button(tab_whois, text="Lookup", bootstyle="primary", command=whois_action).grid(row=0, column=2, padx=5, pady=5)

output_whois = Text(tab_whois, bg="#1e1e1e", fg="#fff", width=90, height=30)
output_whois.grid(row=1, column=0, columnspan=3, padx=10, pady=10)

# ---- Utilities Tab ----
tab_misc = tb.Frame(tabs)
tabs.add(tab_misc, text="🛠 Utilities")

tb.Label(tab_misc, text="Target/Domain:").grid(row=0, column=0, padx=5, pady=5, sticky=E)
entry_misc = tb.Entry(tab_misc, width=30); entry_misc.grid(row=0, column=1, padx=5, pady=5)

tb.Button(tab_misc, text="ICMP TTL", bootstyle="warning", command=ttl_action).grid(row=1, column=0, padx=5, pady=5)
tb.Button(tab_misc, text="Server Info", bootstyle="secondary", command=serverinfo_action).grid(row=1, column=1, padx=5, pady=5)
tb.Button(tab_misc, text="Local IP", bootstyle="info", command=localip_action).grid(row=1, column=2, padx=5, pady=5)

# 🔍 Nmap Scan Options
# Add this below the Local IP button in tab_misc
tb.Label(tab_misc, text="Scan Profile:").grid(row=2, column=0, padx=5, pady=5, sticky=E)

combo_profile = tb.Combobox(tab_misc, values=[
    "Quick Scan (-F)",
    "Aggressive Scan (-A)",
    "OS Detection (-O)",
    "Version Detection (-sV)",
    "Ping Scan (-sn)",
    #"Custom Full Scan (-p- -sC -sV)"
])
combo_profile.set("Aggressive Scan (-A)")
combo_profile.grid(row=2, column=1, padx=5, pady=5, sticky=W)

tb.Button(tab_misc, text="Run Nmap Scan", bootstyle="danger", command=lambda: run_nmap_scan(entry_misc.get(), combo_profile.get())).grid(row=2, column=2, padx=5, pady=5)
tb.Button(tab_misc, text="Aggressive Scan", bootstyle="danger", command=run_aggressive_scan).grid(row=3, column=2, padx=5, pady=5)
# ---- Batch Scan Tab ----
tab_batch = tb.Frame(tabs)
tabs.add(tab_batch, text="📄 Batch Scan")
# Checkboxes for scan types
scan_options = {
    "Quick Scan (-F)": tk.BooleanVar(value=True),
    "Aggressive Full Scan": tk.BooleanVar(),  # 🔁 New label
    "OS Detection (-O)": tk.BooleanVar(),
    "Version Detection (-sV)": tk.BooleanVar()
}

scan_frame = tb.Labelframe(tab_batch, text="Scan Profiles")
scan_frame.pack(padx=10, pady=5, fill="x")

for idx, (label, var) in enumerate(scan_options.items()):
    tb.Checkbutton(scan_frame, text=label, variable=var).grid(row=0, column=idx, padx=10, sticky="w")

tb.Button(tab_batch, text="Import .txt File", bootstyle="primary", command=load_file_action).pack(padx=10, pady=5, anchor="w")
tb.Button(tab_batch, text="Run Batch Scan", bootstyle="danger", command=batch_scan_action).pack(padx=10, pady=5, anchor="w")

label_batch_status = tb.Label(tab_batch, text="No file loaded.", bootstyle="info")
label_batch_status.pack(padx=10, pady=5, anchor="w")

output_batch = Text(tab_batch, bg="#1e1e1e", fg="#fff", width=100, height=30)
output_batch.pack(padx=10, pady=10, fill=BOTH, expand=True)

output_batch.tag_config("nmap", foreground="#66ff66", font=("Consolas", 10))
output_batch.tag_config("error", foreground="red", font=("Consolas", 10, "italic"))

output_misc = Text(tab_misc, bg="#1e1e1e", fg="#fff", width=90, height=25)
output_misc.grid(row=3, column=0, columnspan=3, padx=10, pady=10)
output_misc.tag_config("nmap", foreground="#66ff66", font=("Consolas", 10))
output_misc.tag_config("error", foreground="red", font=("Consolas", 10, "italic"))

app.mainloop()
