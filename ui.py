import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from threading import Thread
import subprocess
import sys
from utils.config import get_interface_info
from utils.logger import get_stats

sniff_process = None
is_sniffing = False

class TextRedirector:
    def __init__(self, text_widget):
        self.text_widget = text_widget

    def write(self, string):
        self.text_widget.insert(tk.END, string)
        self.text_widget.see(tk.END)

    def flush(self):
        pass

def start_sniff():
    global sniff_process, is_sniffing

    if is_sniffing:
        messagebox.showwarning("Warning", "Sniffing already running")
        return

    interface = interface_var.get()
    if interface == "Select interface..." or "Default" in interface:
        interface = None

    packet_filter = filter_var.get()
    if packet_filter == "":
        packet_filter = None

    is_sniffing = True
    start_btn.config(state="disabled")
    stop_btn.config(state="normal")
    status_label.config(text="Status: RUNNING", foreground="green")

    output_text.delete(1.0, tk.END)

    # Build command
    cmd = [sys.executable, "main.py"]
    if packet_filter:
        cmd.extend(["-f", packet_filter])
    if interface and interface != "Default (Scapy auto)":
        cmd.extend(["-i", interface])

    # Start subprocess
    sniff_process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )

    def read_output():
        while is_sniffing and sniff_process:
            try:
                line = sniff_process.stdout.readline()
                if line:
                    output_text.insert(tk.END, line)
                    output_text.see(tk.END)
                else:
                    break
            except:
                break
        # Clean up after process ends
        root.after(0, sniff_finished)

    def sniff_finished():
        global sniff_process, is_sniffing
        if sniff_process:
            sniff_process = None
        is_sniffing = False
        start_btn.config(state="normal")
        stop_btn.config(state="disabled")
        status_label.config(text="Status: STOPPED", foreground="red")
        update_stats()
        output_text.insert(tk.END, "\n[INFO] Sniffing stopped\n")

    Thread(target=read_output, daemon=True).start()

def stop_sniff():
    global sniff_process, is_sniffing
    
    if sniff_process:
        status_label.config(text="Status: STOPPING...", foreground="orange")
        output_text.insert(tk.END, "\n[INFO] Stopping sniffer...\n")
        
        # Kill the subprocess
        sniff_process.terminate()
        try:
            sniff_process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            sniff_process.kill()
        
        sniff_process = None
        is_sniffing = False

def update_stats():
    stats = get_stats()
    stats_label.config(text=f"Total packets: {stats['total_packets']} | Unique IPs: {stats['unique_ips']}")

def refresh_interfaces():
    interfaces = get_interface_info()
    display_names = ["Default (Scapy auto)"] + [f"{iface['name']} ({iface['ip']})" for iface in interfaces if iface['ip'] != "Auto-detected by Scapy"]
    interface_dropdown['values'] = display_names
    if display_names:
        interface_var.set(display_names[0])

def on_closing():
    if is_sniffing:
        if messagebox.askokcancel("Quit", "Sniffing is still running. Stop and quit?"):
            stop_sniff()
            root.after(1000, root.destroy)
    else:
        root.destroy()

root = tk.Tk()
root.title("Network Traffic Analyzer")
root.geometry("900x700")
root.protocol("WM_DELETE_WINDOW", on_closing)

main_frame = ttk.Frame(root, padding="10")
main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

ttk.Label(main_frame, text="Network Interface:").grid(row=0, column=0, sticky=tk.W, pady=5)

interface_var = tk.StringVar(value="Default (Scapy auto)")
interface_dropdown = ttk.Combobox(main_frame, textvariable=interface_var, width=50)
interface_dropdown.grid(row=0, column=1, pady=5, padx=5)

ttk.Button(main_frame, text="Refresh", command=refresh_interfaces).grid(row=0, column=2, pady=5)

ttk.Label(main_frame, text="BPF Filter (optional):").grid(row=1, column=0, sticky=tk.W, pady=5)
filter_var = tk.StringVar()
filter_entry = ttk.Entry(main_frame, textvariable=filter_var, width=60)
filter_entry.grid(row=1, column=1, pady=5, padx=5)
ttk.Label(main_frame, text="e.g., 'host 10.76.23.80' or 'tcp port 80'", foreground="gray").grid(row=1, column=2, sticky=tk.W)

button_frame = ttk.Frame(main_frame)
button_frame.grid(row=2, column=0, columnspan=3, pady=10)

start_btn = ttk.Button(button_frame, text="Start Sniffing", command=start_sniff)
start_btn.pack(side=tk.LEFT, padx=5)

stop_btn = ttk.Button(button_frame, text="Stop", command=stop_sniff, state="disabled")
stop_btn.pack(side=tk.LEFT, padx=5)

ttk.Button(button_frame, text="Refresh Stats", command=update_stats).pack(side=tk.LEFT, padx=5)
ttk.Button(button_frame, text="Clear Log", command=lambda: output_text.delete(1.0, tk.END)).pack(side=tk.LEFT, padx=5)

status_label = ttk.Label(main_frame, text="Status: STOPPED", foreground="red")
status_label.grid(row=3, column=0, columnspan=3, pady=5)

stats_label = ttk.Label(main_frame, text="Total packets: 0 | Unique IPs: 0")
stats_label.grid(row=4, column=0, columnspan=3, pady=5)

ttk.Label(main_frame, text="Packet Log:").grid(row=5, column=0, sticky=tk.W, pady=5)

output_text = scrolledtext.ScrolledText(main_frame, width=100, height=30, font=("Courier", 9))
output_text.grid(row=6, column=0, columnspan=3, pady=5)

refresh_interfaces()
update_stats()

root.mainloop()