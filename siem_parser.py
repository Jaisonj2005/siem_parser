import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import re
from collections import Counter
import threading
import os

def generate_sample_log():
    sample_path = os.path.join(os.getcwd(), "sample_auth.log")
    log_data = """
Oct 11 10:00:01 server1 sshd[1234]: Accepted publickey for admin from 192.168.1.50 port 50212 ssh2
Oct 11 10:05:12 server1 sshd[1289]: Failed password for root from 203.0.113.42 port 33921 ssh2
Oct 11 10:05:14 server1 sshd[1289]: Failed password for root from 203.0.113.42 port 33925 ssh2
Oct 11 10:05:17 server1 sshd[1289]: Failed password for root from 203.0.113.42 port 33929 ssh2
Oct 11 10:12:45 server1 sudo[1402]: pam_unix(sudo:session): session opened for user root
Oct 11 10:15:22 server1 sshd[1501]: Invalid user admin from 198.51.100.7 port 44321
Oct 11 10:15:24 server1 sshd[1501]: Failed password for invalid user admin from 198.51.100.7 port 44321 ssh2
Oct 11 10:18:00 server1 sshd[1555]: Connection closed by 104.16.85.20 port 55122 [preauth]
"""
    try:
        with open(sample_path, "w") as f:
            f.write(log_data.strip())
        entry_filepath.config(state=tk.NORMAL)
        entry_filepath.delete(0, tk.END)
        entry_filepath.insert(0, sample_path)
        entry_filepath.config(state="readonly")
        messagebox.showinfo("Success", f"Sample log generated at:\n{sample_path}")
    except Exception as e:
        messagebox.showerror("Error", f"Could not create sample log: {e}")

def select_file():
    filepath = filedialog.askopenfilename(title="Select Log File", filetypes=[("Log Files", "*.log *.txt"), ("All Files", "*.*")])
    if filepath:
        entry_filepath.config(state=tk.NORMAL)
        entry_filepath.delete(0, tk.END)
        entry_filepath.insert(0, filepath)
        entry_filepath.config(state="readonly")

def start_parsing():
    filepath = entry_filepath.get()
    if not filepath or filepath == "No log file selected...":
        messagebox.showwarning("Input Error", "Please select a log file to parse.")
        return
        
    btn_parse.config(state=tk.DISABLED)
    text_output.config(state=tk.NORMAL)
    text_output.delete(1.0, tk.END)
    text_output.insert(tk.END, f"[*] Analyzing log file: {os.path.basename(filepath)}\n")
    text_output.insert(tk.END, "-" * 55 + "\n")
    text_output.config(state=tk.DISABLED)
    
    lbl_status.config(text="Parsing logs...", fg="#e67e22")
    
    threading.Thread(target=parse_logs, args=(filepath,), daemon=True).start()

def parse_logs(filepath):
    # Regex to find IPv4 addresses
    ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    
    failed_ips = []
    line_count = 0
    
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line_count += 1
                # Hunt for standard SSH brute-force indicators
                if "Failed password" in line or "Invalid user" in line:
                    match = ip_pattern.search(line)
                    if match:
                        failed_ips.append(match.group())
                        
        # Tally up the IPs
        ip_counts = Counter(failed_ips)
        
        insert_log(f"[*] Processed {line_count} lines.\n")
        insert_log(f"[*] Found {len(ip_counts)} unique attacker IPs.\n\n")
        
        if ip_counts:
            insert_log("BRUTE-FORCE ATTEMPT SUMMARY (Target IPs):\n", "warning")
            for ip, count in ip_counts.most_common():
                if count > 2:
                    insert_log(f"  [!] {ip} - {count} failed attempts (HIGH RISK)\n", "error")
                else:
                    insert_log(f"  [-] {ip} - {count} failed attempts\n")
        else:
            insert_log("No failed login indicators found in this log.", "success")
            
        lbl_status.config(text="Parsing Complete", fg="#27ae60")
        
    except Exception as e:
        insert_log(f"\n[!] Error reading file: {e}", "error")
        lbl_status.config(text="Error", fg="#c0392b")
        
    finally:
        root.after(0, lambda: btn_parse.config(state=tk.NORMAL))

def insert_log(message, tag=None):
    text_output.config(state=tk.NORMAL)
    text_output.insert(tk.END, message, tag)
    text_output.see(tk.END)
    text_output.config(state=tk.DISABLED)

# --- Tkinter GUI Layout ---
root = tk.Tk()
root.title("SOC Toolkit - SIEM Log Parser")
root.geometry("650x500")
root.resizable(False, False)

frame = ttk.Frame(root, padding="15")
frame.pack(fill=tk.BOTH, expand=True)

lbl_title = tk.Label(frame, text="Auth Log IoC Extractor", font=("Helvetica", 13, "bold"))
lbl_title.pack(anchor="w", pady=(0, 5))
lbl_desc = tk.Label(frame, text="Extracts and tallies brute-force attacker IPs from raw server logs.", font=("Helvetica", 9), fg="#555")
lbl_desc.pack(anchor="w", pady=(0, 15))

# File Configuration
config_frame = tk.Frame(frame)
config_frame.pack(fill=tk.X, pady=(0, 15))

entry_filepath = ttk.Entry(config_frame, width=50, font=("Consolas", 10))
entry_filepath.pack(side=tk.LEFT, padx=(0, 10))
entry_filepath.insert(0, "No log file selected...")
entry_filepath.config(state="readonly")

btn_browse = tk.Button(config_frame, text="Browse...", command=select_file, font=("Helvetica", 9))
btn_browse.pack(side=tk.LEFT, padx=(0, 10))

btn_generate = tk.Button(config_frame, text="Generate Sample", command=generate_sample_log, bg="#8e44ad", fg="white", font=("Helvetica", 9))
btn_generate.pack(side=tk.LEFT)

# Controls
control_frame = tk.Frame(frame)
control_frame.pack(fill=tk.X, pady=(10, 10))

btn_parse = tk.Button(control_frame, text="Analyze Logs", command=start_parsing, bg="#2980b9", fg="white", font=("Helvetica", 10, "bold"), width=15)
btn_parse.pack(side=tk.LEFT)

lbl_status = tk.Label(control_frame, text="Ready", font=("Consolas", 9), fg="#7f8c8d")
lbl_status.pack(side=tk.RIGHT, padx=(0, 5))

# Output Console
text_frame = tk.Frame(frame)
text_frame.pack(fill=tk.BOTH, expand=True)

scrollbar = tk.Scrollbar(text_frame)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

text_output = tk.Text(text_frame, font=("Consolas", 10), bg="#1e1e1e", fg="#ecf0f1", yscrollcommand=scrollbar.set)
text_output.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
text_output.tag_config("success", foreground="#2ecc71")
text_output.tag_config("warning", foreground="#f1c40f")
text_output.tag_config("error", foreground="#e74c3c")
text_output.config(state=tk.DISABLED)

scrollbar.config(command=text_output.yview)

root.mainloop()