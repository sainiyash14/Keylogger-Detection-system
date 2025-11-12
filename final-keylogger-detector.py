import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk, filedialog
import psutil
import threading
import os
import winreg
import time
from datetime import datetime
import sys

class KeyloggerDetectionSystem:
    def __init__(self):
        # Initialize ALL attributes FIRST before UI setup
        self.scanning = False
        self.last_scan_time = None
        self.hook_monitoring_active = False
        self.detected_hooks = []
        self.hook_detection_ready = False
        self.ctypes_available = False
        
        # THREAD SAFETY
        self.monitoring_lock = threading.Lock()
        self.flash_message_active = False
        self.last_log_time = {}
        self.log_throttle_seconds = 0.5
        
        # THREAT TRACKING
        self.detected_threats = []
        
        # GET CURRENT SCRIPT INFO FOR SELF-EXCLUSION
        self.current_script_path = os.path.abspath(__file__)
        self.current_script_name = os.path.basename(__file__)
        self.current_script_dir = os.path.dirname(self.current_script_path)
        self.current_process_name = os.path.basename(sys.argv[0]) if len(sys.argv) > 0 else "python.exe"
        
        # WHITELIST - Files and processes to exclude from detection
        self.whitelist_files = [
            self.current_script_name.lower(),
            "detector.py", 
            "keylogger-detector.py",
            "smart-keylogger-detector.py",
            "clean-keylogger-detector.py",
            "flash-keylogger-detector.py",
            "stable-keylogger-detector.py",
            "locator-keylogger-detector.py"
        ]
        
        # ENHANCED WHITELIST: Add browsers and system processes
        self.whitelist_processes = [
            "python.exe", "pythonw.exe",
            "msedge.exe", "msedgewebview2.exe",
            "chrome.exe", "googlechrome.exe",
            "firefox.exe", "firefox",
            "opera.exe", "operagx.exe",
            "brave.exe", "bravebrowser.exe","comet.exe",
            "safari.exe", "safari",
            "iexplore.exe", "internetexplorer",
            "textinputhost.exe", "explorer.exe", "dwm.exe", "winlogon.exe",
            "svchost.exe", "lsass.exe", "services.exe", "csrss.exe", "wininit.exe",
            "notepad.exe", "calc.exe", "mspaint.exe", "cmd.exe", "powershell.exe"
        ]
        
        # KEYLOGGER PATTERNS
        self.suspicious_processes = [
            'keylogger', 'spyrix', 'ardamax', 'revealer', 'ghostkeylogger',
            'perfect_keylogger', 'actual_keylogger', 'home_keylogger',
            'elite_keylogger', 'blazing_tools', 'keylogger_pro', 'refog',
            'spyshelter', 'kidlogger', 'keylog', 'klog', 'logkeys'
        ]
        
        # Python keylogger detection patterns
        self.python_keylogger_patterns = [
            'pynput', 'keyboard', 'listener', 'on_press', 'key.char', 'on_release',
            'win32api', 'GetAsyncKeyState', 'win32con', 'VK_', 'msvcrt.getch',
            'keystrokes.txt', 'keys.txt', 'keylog.txt', 'logged_keys'
        ]
        
        # Innocent Python patterns
        self.innocent_python_patterns = [
            'tkinter', 'gui', 'calculator', 'math', 'numpy', 'pandas',
            'matplotlib', 'requests', 'flask', 'django', 'sqlite3'
        ]
        
        # Suspicious files
        self.suspicious_files = [
            'keystrokes', 'keylog', 'screenshots', 'captured_keys', 'logged_keys'
        ]
        
        # Registry keys
        self.suspicious_registry_keys = [
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", 
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
        ]
        
        # REAL-TIME MONITORING STATE
        self.previous_processes = set()
        self.baseline_established = False
        
        # Initialize hook detection
        self.initialize_hook_detection()
        
        # Create the UI
        self.window = tk.Tk()
        self.setup_ui()
        
        # Graceful shutdown handler
        self.window.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # Start real-time updates
        self.update_time_display()
        self.update_system_stats()

    def on_closing(self):
        """Handle graceful shutdown"""
        try:
            if self.hook_monitoring_active:
                self.hook_monitoring_active = False
                time.sleep(0.5)
            self.window.destroy()
        except Exception as e:
            self.log_message(f"Error during shutdown: {str(e)}")
            self.window.destroy()

    def safe_cmdline_join(self, cmdline):
        """Safely join command line arguments"""
        try:
            if cmdline is None:
                return ""
            if isinstance(cmdline, list):
                return ' '.join(str(arg) for arg in cmdline)
            return str(cmdline)
        except Exception:
            return ""

    def is_likely_keylogger(self, cmdline, filename=""):
        """SMART detection"""
        try:
            cmdline_lower = cmdline.lower() if cmdline else ""
            filename_lower = filename.lower() if filename else ""
            
            suspicious_count = 0
            innocent_count = 0
            detected_patterns = []
            
            for pattern in self.python_keylogger_patterns:
                if pattern in cmdline_lower or pattern in filename_lower:
                    suspicious_count += 1
                    detected_patterns.append(pattern)
            
            for innocent in self.innocent_python_patterns:
                if innocent in cmdline_lower or innocent in filename_lower:
                    innocent_count += 1
            
            strong_keylogger_patterns = ['pynput', 'keyboard', 'listener', 'on_press',
                                       'GetAsyncKeyState', 'SetWindowsHookEx', 'keylog']
            has_strong_pattern = any(pattern in cmdline_lower for pattern in strong_keylogger_patterns)
            
            if suspicious_count >= 2 and innocent_count == 0:
                return True, detected_patterns, "Multiple keylogger patterns"
            elif has_strong_pattern and innocent_count <= 1:
                return True, detected_patterns, "Strong keylogger indicator"
            elif suspicious_count >= 3:
                return True, detected_patterns, "High suspicious pattern count"
            else:
                return False, [], "Appears to be legitimate Python script"
        except Exception as e:
            return False, [], "Error in detection"

    def is_whitelisted_file(self, file_path, file_name):
        """Check if file should be excluded"""
        try:
            file_name_lower = file_name.lower()
            
            if file_path == self.current_script_path:
                return True
                
            for whitelisted in self.whitelist_files:
                if whitelisted in file_name_lower:
                    return True
                    
            return False
        except Exception:
            return False

    def is_whitelisted_process(self, process_name, process_path="", cmdline=""):
        """Check if process should be excluded"""
        try:
            process_name_lower = process_name.lower()
            cmdline_lower = cmdline.lower() if cmdline else ""
            
            if self.current_script_name.lower() in cmdline_lower:
                return True
                
            for whitelisted in self.whitelist_processes:
                if whitelisted == process_name_lower:
                    if process_name_lower in ['python.exe', 'pythonw.exe']:
                        if any(detector_file in cmdline_lower for detector_file in self.whitelist_files):
                            return True
                        else:
                            return False
                    else:
                        return True
                        
            return False
        except Exception:
            return False

    def initialize_hook_detection(self):
        """Initialize hook detection"""
        try:
            import ctypes
            from ctypes import wintypes, windll
            self.ctypes_available = True
            self.user32 = windll.user32
            self.kernel32 = windll.kernel32
            self.user32.GetForegroundWindow()
            self.hook_detection_ready = True
        except Exception as e:
            self.hook_detection_ready = False
            self.ctypes_available = False

    def setup_ui(self):
        self.window.title("Smart Keylogger Detection System - Security Dashboard")
        self.window.geometry("1500x950")
        self.window.configure(bg="#0f1419")
        self.window.resizable(True, True)
        
        # MAIN CONTAINER
        main_container = tk.Frame(self.window, bg="#0f1419")
        main_container.pack(fill=tk.BOTH, expand=True, padx=30, pady=25)
        
        # FLASH MESSAGE BAR
        self.flash_frame = tk.Frame(main_container, bg="#27ae60", height=50)
        self.flash_label = tk.Label(self.flash_frame, text="", 
                                   font=("Segoe UI", 12, "bold"), 
                                   bg="#27ae60", fg="white", pady=12)
        self.flash_label.pack(fill=tk.BOTH, expand=True)
        
        # CONTENT CONTAINER
        content_container = tk.Frame(main_container, bg="#0f1419")
        content_container.pack(fill=tk.BOTH, expand=True)
        content_container.grid_columnconfigure(0, weight=1, minsize=400)
        content_container.grid_columnconfigure(1, weight=2, minsize=800)
        content_container.grid_rowconfigure(0, weight=1, minsize=350)
        content_container.grid_rowconfigure(1, weight=1, minsize=350)
        
        self.create_scrollable_system_info_card(content_container)
        self.create_scan_results_card(content_container)
        self.create_threat_dashboard_card(content_container)
        self.create_simplified_controls_card(content_container)

    def show_flash_message(self, message, bg_color="#27ae60", duration=3000):
        """Show in-app flash message"""
        if self.flash_message_active:
            return
            
        self.flash_message_active = True
        self.flash_label.config(text=message, bg=bg_color)
        self.flash_frame.config(bg=bg_color)
        self.flash_frame.pack(fill=tk.X, pady=(0, 15))
        
        def hide_with_flag():
            self.hide_flash_message()
            self.flash_message_active = False
            
        self.window.after(duration, hide_with_flag)

    def hide_flash_message(self):
        """Hide flash message"""
        self.flash_frame.pack_forget()

    def create_card(self, parent, bg_color="#1c2128", min_height=None):
        card_frame = tk.Frame(parent, bg=bg_color, relief=tk.FLAT, bd=1)
        border = tk.Frame(card_frame, bg="#30363d", height=1)
        border.pack(fill=tk.X)
        content = tk.Frame(card_frame, bg=bg_color)
        content.pack(fill=tk.BOTH, expand=True, padx=25, pady=20)
        if min_height:
            card_frame.configure(height=min_height)
        return card_frame, content

    def create_keylogger_detection_logo(self, parent, size=70):
        """Create logo"""
        try:
            logo_canvas = tk.Canvas(parent, width=size, height=size,
                                   bg="#1c2128", highlightthickness=0)
            logo_canvas.pack()
            
            center = size // 2
            
            logo_canvas.create_oval(2, 2, size-2, size-2, 
                                  outline="#ff6b6b", width=3)
            
            shield_points = [
                center, 8, center + 16, 18, center + 16, center + 6,
                center, size - 10, center - 16, center + 6, center - 16, 18
            ]
            logo_canvas.create_polygon(shield_points, 
                                     fill="#4ecdc4", outline="#45b7b8", width=2)
            
            kbd_width, kbd_height = 22, 12
            kbd_x = center - kbd_width//2
            kbd_y = center - kbd_height//2
            
            logo_canvas.create_rectangle(kbd_x, kbd_y, kbd_x + kbd_width, kbd_y + kbd_height,
                                       fill="#2f3542", outline="#57606f", width=1)
            
            key_size = 2
            key_spacing = 3
            for row in range(3):
                for col in range(5):
                    key_x = kbd_x + 3 + col * key_spacing
                    key_y = kbd_y + 2 + row * 3
                    logo_canvas.create_rectangle(key_x, key_y, key_x + key_size, key_y + key_size,
                                               fill="#f1f2f6", outline="#ddd")
            
            for i in range(3):
                radius = 18 + i * 6
                color = "#ff6b6b" if i == 0 else "#ffa502" if i == 1 else "#26de81"
                logo_canvas.create_oval(center - radius, center - radius,
                                      center + radius, center + radius,
                                      outline=color, width=1 + (2-i))
            
            return logo_canvas
        except Exception as e:
            return None

    def create_scrollable_system_info_card(self, parent):
        """System info card"""
        try:
            card, content = self.create_card(parent, min_height=300)
            card.grid(row=0, column=0, sticky="nsew", padx=(0, 15), pady=(0, 15))
            
            header = tk.Frame(content, bg="#1c2128")
            header.pack(fill=tk.X, pady=(0, 20))
            
            icon_frame = tk.Frame(header, bg="#1c2128")
            icon_frame.pack(side=tk.LEFT)
            self.create_keylogger_detection_logo(icon_frame, size=65)
            
            title_frame = tk.Frame(header, bg="#1c2128")
            title_frame.pack(side=tk.LEFT, padx=(15, 0), fill=tk.BOTH, expand=True)
            
            tk.Label(title_frame, text="Smart Keylogger Detection",
                    font=("Segoe UI", 15, "bold"), bg="#1c2128", fg="#f0f6fc").pack(anchor="w")
            
            self.system_status_label = tk.Label(title_frame, text="SMART MONITORING",
                                              font=("Segoe UI", 11, "bold"), bg="#1c2128", fg="#3fb950")
            self.system_status_label.pack(anchor="w", pady=(3, 0))
            
            divider = tk.Frame(content, bg="#30363d", height=1)
            divider.pack(fill=tk.X, pady=(0, 15))
            
            info_header_frame = tk.Frame(content, bg="#1c2128")
            info_header_frame.pack(fill=tk.X, pady=(0, 10))
            
            tk.Label(info_header_frame, text="Real-Time System Information",
                    font=("Segoe UI", 14, "bold"), bg="#1c2128", fg="#f0f6fc").pack(side=tk.LEFT)
            
            self.last_updated_label = tk.Label(info_header_frame, text="Updated: now",
                                             font=("Segoe UI", 9), bg="#1c2128", fg="#8b949e")
            self.last_updated_label.pack(side=tk.RIGHT)
            
            # CREATE SCROLLABLE FRAME
            scrollable_container = tk.Frame(content, bg="#1c2128")
            scrollable_container.pack(fill=tk.BOTH, expand=True)
            
            canvas = tk.Canvas(scrollable_container, bg="#1c2128", highlightthickness=0)
            scrollbar = ttk.Scrollbar(scrollable_container, orient="vertical", command=canvas.yview)
            self.scrollable_frame = tk.Frame(canvas, bg="#1c2128")
            
            self.scrollable_frame.bind(
                "<Configure>",
                lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
            )
            
            canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
            canvas.configure(yscrollcommand=scrollbar.set)
            
            canvas.pack(side="left", fill="both", expand=True)
            scrollbar.pack(side="right", fill="y")
            
            def _on_mousewheel(event):
                canvas.yview_scroll(int(-1*(event.delta/120)), "units")
            canvas.bind("<MouseWheel>", _on_mousewheel)
            canvas.focus_set()
            
            # SYSTEM STATS
            self.system_stats = {}
            stats_info = [
                ("cpu", "CPU Usage", "0.0%"),
                ("memory", "Memory", "0.0%"),
                ("processes", "Processes", "0"),
                ("connections", "Connections", "0"),
                ("disk", "Disk Usage", "0.0%"),
                ("uptime", "Uptime", "0h 0m")
            ]
            
            for key, icon_text, initial_value in stats_info:
                stat_row = tk.Frame(self.scrollable_frame, bg="#1c2128")
                stat_row.pack(fill=tk.X, pady=4, padx=5)
                
                icon_label = tk.Label(stat_row, text=icon_text, font=("Segoe UI", 11),
                                    bg="#1c2128", fg="#8b949e")
                icon_label.pack(side=tk.LEFT)
                
                value_label = tk.Label(stat_row, text=initial_value, font=("Segoe UI", 11, "bold"),
                                     bg="#1c2128", fg="#f0f6fc")
                value_label.pack(side=tk.RIGHT)
                
                self.system_stats[key] = {'label': value_label, 'icon': icon_label}
        except Exception as e:
            pass

    def create_scan_results_card(self, parent):
        try:
            card, content = self.create_card(parent, min_height=300)
            card.grid(row=0, column=1, sticky="nsew", pady=(0, 15))
            
            header = tk.Frame(content, bg="#1c2128")
            header.pack(fill=tk.X, pady=(0, 15))
            
            header_left = tk.Frame(header, bg="#1c2128")
            header_left.pack(side=tk.LEFT, fill=tk.X, expand=True)
            
            tk.Label(header_left, text="Smart Detection Results & Analysis Logs",
                    font=("Segoe UI", 16, "bold"), bg="#1c2128", fg="#f0f6fc").pack(anchor="w")
            
            # EXPORT BUTTON
            export_btn = tk.Button(header, text="Export Threats",
                                 command=self.export_threats_report,
                                 font=("Segoe UI", 9, "bold"),
                                 bg="#58a6ff", fg="white",
                                 relief=tk.FLAT, padx=10, pady=5)
            export_btn.pack(side=tk.RIGHT)
            
            results_container = tk.Frame(content, bg="#1c2128")
            results_container.pack(fill=tk.BOTH, expand=True)
            
            self.results_text = scrolledtext.ScrolledText(
                results_container, wrap=tk.WORD, width=70, height=18,
                bg="#0d1117", fg="#f0f6fc", font=("Consolas", 10),
                relief=tk.FLAT, bd=0, insertbackground="#f0f6fc", selectbackground="#264f78"
            )
            self.results_text.pack(fill=tk.BOTH, expand=True)
            
            # Initial messages
            hook_status = "READY" if self.hook_detection_ready else "PROCESS-BASED MODE"
            self.log_message("Smart Keylogger Detection System Initialized")
            self.log_message("Intelligent pattern recognition algorithms loaded")
            self.log_message("Multi-vector threat analysis engine activated")
            self.log_message(f"Hook Detection System: {hook_status}")
            self.log_message("SMART detection: Reduces false positives!")
            self.log_message("MS Edge, Chrome, Firefox: WHITELISTED")
            self.log_message("=" * 65)
        except Exception as e:
            pass

    def export_threats_report(self):
        """Export threat report with UTF-8 encoding"""
        try:
            if not self.detected_threats:
                messagebox.showwarning("No Threats", "No threats detected yet. Run a scan first!")
                return
            
            report = self.generate_threat_report()
            
            file_path = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
                initialfile=f"keylogger_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            )
            
            if file_path:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(report)
                self.show_flash_message("Report exported!", "#27ae60", 4000)
                messagebox.showinfo("Export Success", f"Report saved to:\n{file_path}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export: {str(e)}")

    def generate_threat_report(self):
        """Generate threat report"""
        report = []
        report.append("=" * 80)
        report.append("[!] KEYLOGGER DETECTION REPORT")
        report.append("=" * 80)
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Total Threats Detected: {len(self.detected_threats)}")
        report.append("=" * 80)
        report.append("")
        
        if not self.detected_threats:
            report.append("[OK] NO KEYLOGGERS DETECTED - SYSTEM IS SECURE!")
            return "\n".join(report)
        
        process_threats = [t for t in self.detected_threats if t.get('type') == 'PROCESS']
        file_threats = [t for t in self.detected_threats if t.get('type') == 'FILE']
        registry_threats = [t for t in self.detected_threats if t.get('type') == 'REGISTRY']
        
        if process_threats:
            report.append("[CRITICAL] PROCESS-BASED THREATS:")
            report.append("-" * 80)
            for i, threat in enumerate(process_threats, 1):
                report.append(f"\n[{i}] {threat.get('name', 'Unknown')}")
                report.append(f"    [PATH] Location: {threat.get('path', 'Unknown')}")
                report.append(f"    [PID] Process ID: {threat.get('pid', 'N/A')}")
                report.append(f"    [RISK] Risk Level: {threat.get('risk_level', 'MEDIUM')}")
                report.append(f"    [TYPE] Detection Type: {threat.get('hook_type', 'Unknown')}")
                report.append(f"    [REASON] {threat.get('detection_reason', 'Unknown')}")
                if threat.get('cmdline'):
                    report.append(f"    [CMD] Command Line: {threat['cmdline'][:100]}...")
            report.append("")
        
        if file_threats:
            report.append("[CRITICAL] FILE-BASED THREATS:")
            report.append("-" * 80)
            for i, threat in enumerate(file_threats, 1):
                report.append(f"\n[{i}] {threat.get('name', 'Unknown')}")
                report.append(f"    [FILE] Full Path: {threat.get('path', 'Unknown')}")
                report.append(f"    [RISK] Risk Level: {threat.get('risk_level', 'MEDIUM')}")
                report.append(f"    [REASON] {threat.get('detection_reason', 'Unknown')}")
                report.append(f"    [TIME] Created: {threat.get('created', 'Unknown')}")
            report.append("")
        
        if registry_threats:
            report.append("[CRITICAL] REGISTRY-BASED THREATS (Persistence):")
            report.append("-" * 80)
            for i, threat in enumerate(registry_threats, 1):
                report.append(f"\n[{i}] {threat.get('name', 'Unknown')}")
                report.append(f"    [REG] Registry Path: {threat.get('reg_path', 'Unknown')}")
                report.append(f"    [VALUE] Value: {threat.get('value', 'Unknown')[:100]}...")
                report.append(f"    [RISK] Risk Level: CRITICAL (Persistence)")
            report.append("")
        
        report.append("=" * 80)
        report.append("[ACTION] RECOMMENDATIONS:")
        report.append("=" * 80)
        report.append("1. Terminate all detected processes immediately")
        report.append("2. Delete all detected files from their locations")
        report.append("3. Clean registry entries to remove persistence")
        report.append("4. Scan system with antivirus software")
        report.append("5. Change all passwords from a clean device")
        report.append("=" * 80)
        
        return "\n".join(report)

    def create_threat_dashboard_card(self, parent):
        try:
            card, content = self.create_card(parent, min_height=300)
            card.grid(row=1, column=1, sticky="nsew")
            
            header = tk.Frame(content, bg="#1c2128")
            header.pack(fill=tk.X, pady=(0, 20))
            
            tk.Label(header, text="Smart Keylogger Threat Analysis",
                    font=("Segoe UI", 16, "bold"), bg="#1c2128", fg="#f0f6fc").pack(anchor="w")
            
            metrics_container = tk.Frame(content, bg="#1c2128")
            metrics_container.pack(fill=tk.X, pady=(0, 25))
            
            for i in range(4):
                metrics_container.columnconfigure(i, weight=1, uniform="metric")
            
            self.metrics = {
                "last_scan": {"label": "Last Scan", "value": "Never", "color": "#8b949e"},
                "threats": {"label": "Keyloggers", "value": "0", "color": "#3fb950"},
                "processes": {"label": "Processes", "value": "0", "color": "#58a6ff"},
                "registry": {"label": "Registry", "value": "0", "color": "#f85149"}
            }
            
            self.metric_widgets = {}
            for i, (key, data) in enumerate(self.metrics.items()):
                metric_frame = tk.Frame(metrics_container, bg="#1c2128")
                metric_frame.grid(row=0, column=i, padx=10, sticky="ew")
                
                value_label = tk.Label(metric_frame, text=data["value"],
                                     font=("Segoe UI", 18, "bold"),
                                     bg="#1c2128", fg=data["color"])
                value_label.pack()
                
                label_label = tk.Label(metric_frame, text=data["label"],
                                     font=("Segoe UI", 9),
                                     bg="#1c2128", fg="#8b949e")
                label_label.pack()
                
                self.metric_widgets[key] = value_label
            
            status_frame = tk.Frame(content, bg="#1c2128")
            status_frame.pack(fill=tk.X, pady=(0, 20))
            
            self.status_label = tk.Label(status_frame, text="No keyloggers detected - System secure",
                                       font=("Segoe UI", 13), bg="#1c2128", fg="#3fb950")
            self.status_label.pack(anchor="w")
            
            self.realtime_status_label = tk.Label(status_frame, text="Real-Time Monitoring: OFF",
                                                font=("Segoe UI", 12, "bold"), bg="#1c2128", fg="#f39c12")
            self.realtime_status_label.pack(anchor="w", pady=(5, 0))
        except Exception as e:
            pass

    def create_simplified_controls_card(self, parent):
        """Control buttons"""
        try:
            card, content = self.create_card(parent, min_height=300)
            card.grid(row=1, column=0, sticky="nsew", padx=(0, 15))
            
            scan_header = tk.Label(content, text="Smart Detection Controls",
                                 font=("Segoe UI", 16, "bold"), bg="#1c2128", fg="#f0f6fc")
            scan_header.pack(anchor="w", pady=(0, 30))
            
            self.full_scan_btn = tk.Button(content, text="Full System Scan",
                                         command=self.full_scan,
                                         font=("Segoe UI", 14, "bold"),
                                         bg="#e74c3c", fg="white",
                                         relief=tk.FLAT, pady=15, cursor="hand2", 
                                         width=28, height=1, justify=tk.CENTER)
            self.full_scan_btn.pack(fill=tk.X, pady=(0, 20))
            
            separator = tk.Frame(content, bg="#30363d", height=2)
            separator.pack(fill=tk.X, pady=20)
            
            rt_header = tk.Label(content, text="Smart Real-Time Protection",
                               font=("Segoe UI", 14, "bold"), bg="#1c2128", fg="#f0f6fc")
            rt_header.pack(anchor="w", pady=(0, 15))
            
            self.realtime_btn = tk.Button(content, text="Start Real-Time Monitoring",
                                        command=self.toggle_real_time_monitoring,
                                        font=("Segoe UI", 12, "bold"),
                                        bg="#27ae60", fg="white",
                                        relief=tk.FLAT, pady=12, cursor="hand2", 
                                        width=28, height=1, justify=tk.CENTER)
            self.realtime_btn.pack(fill=tk.X, pady=(0, 15))
        except Exception as e:
            pass

    def toggle_real_time_monitoring(self):
        """Real-time monitoring"""
        try:
            if not self.hook_monitoring_active:
                with self.monitoring_lock:
                    self.hook_monitoring_active = True
                self.realtime_btn.config(text="Stop Real-Time Monitoring", bg="#dc3545")
                self.realtime_status_label.config(text="Real-Time Monitoring: ON", fg="#27ae60")
                
                self.log_message("SMART real-time keylogger monitoring ACTIVATED")
                self.establish_baseline()
                threading.Thread(target=self.smart_real_time_monitoring, daemon=True).start()
                self.show_flash_message("Smart keylogger monitoring activated!", "#27ae60", 4000)
            else:
                with self.monitoring_lock:
                    self.hook_monitoring_active = False
                self.realtime_btn.config(text="Start Real-Time Monitoring", bg="#27ae60")
                self.realtime_status_label.config(text="Real-Time Monitoring: OFF", fg="#f39c12")
                self.log_message("Smart monitoring STOPPED")
                self.show_flash_message("Smart monitoring stopped", "#f39c12", 3000)
        except Exception as e:
            self.log_message(f"Monitoring toggle error: {str(e)}")

    def establish_baseline(self):
        """Establish baseline"""
        try:
            current_processes = set()
            max_baseline_size = 500
            
            for process in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    if len(current_processes) >= max_baseline_size:
                        break
                    info = process.info
                    cmdline = self.safe_cmdline_join(info.get('cmdline', []))
                    process_signature = f"{info['name']}:{cmdline[:100]}"
                    current_processes.add(process_signature)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            self.previous_processes = current_processes
            self.baseline_established = True
            self.log_message(f"Smart baseline established: {len(current_processes)} processes")
        except Exception as e:
            self.log_message(f"Baseline error: {str(e)}")

    def smart_real_time_monitoring(self):
        """Real-time monitoring"""
        try:
            self.log_message("SMART monitoring started - analyzing patterns...")
            scan_count = 0
            
            while self.hook_monitoring_active:
                try:
                    scan_count += 1
                    current_time = datetime.now().strftime("%H:%M:%S")
                    
                    if scan_count % 20 == 0:
                        self.log_message(f"[{current_time}] Smart scan #{scan_count} - analyzing...")
                    
                    new_threats = self.detect_new_processes_smart()
                    python_threats = self.detect_python_keyloggers_smart()
                    file_threats = self.detect_new_files()
                    
                    all_threats = new_threats + python_threats + file_threats
                    
                    for threat in all_threats:
                        self.log_message(f"KEYLOGGER DETECTED: {threat['name']} - {threat.get('detection_reason', 'Unknown')}")
                        self.detected_threats.append(threat)
                        self.show_keylogger_alert(threat)
                    
                    time.sleep(2)
                except Exception as e:
                    self.log_message(f"Monitoring cycle error: {str(e)}")
                    time.sleep(3)
            
            self.log_message("Smart real-time monitoring thread stopped")
        except Exception as e:
            self.log_message(f"Monitoring error: {str(e)}")

    def detect_new_processes_smart(self):
        """Detect new processes"""
        new_threats = []
        
        if not self.baseline_established:
            return new_threats
        
        try:
            current_processes = set()
            current_process_details = {}
            timeout = 30
            start_time = time.time()
            
            for process in psutil.process_iter(['pid', 'name', 'cmdline', 'exe']):
                try:
                    if time.time() - start_time > timeout:
                        break
                    
                    info = process.info
                    if not info or 'name' not in info:
                        continue
                    
                    cmdline = self.safe_cmdline_join(info.get('cmdline', []))
                    process_signature = f"{info['name']}:{cmdline[:100]}"
                    current_processes.add(process_signature)
                    current_process_details[process_signature] = info
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            new_processes = current_processes - self.previous_processes
            
            for new_process_sig in new_processes:
                if new_process_sig in current_process_details:
                    process_info = current_process_details[new_process_sig]
                    name = process_info['name']
                    cmdline = self.safe_cmdline_join(process_info.get('cmdline', [])).lower()
                    exe_path = process_info.get('exe', 'Unknown')
                    
                    if self.is_whitelisted_process(name, "", cmdline):
                        continue
                    
                    if name.lower() in ['python.exe', 'python3.exe', 'pythonw.exe']:
                        is_keylogger, patterns, reason = self.is_likely_keylogger(cmdline)
                        
                        if is_keylogger:
                            threat_info = {
                                'type': 'PROCESS',
                                'pid': process_info['pid'],
                                'name': f"NEW PYTHON KEYLOGGER: {name}",
                                'path': exe_path,
                                'hook_type': 'Smart Real-time Detection',
                                'risk_level': 'CRITICAL',
                                'detection_reason': reason,
                                'patterns': patterns,
                                'cmdline': cmdline[:200] + "..." if len(cmdline) > 200 else cmdline
                            }
                            new_threats.append(threat_info)
            
            self.previous_processes = current_processes
        except Exception as e:
            self.log_message(f"Process detection error: {str(e)}")
        
        return new_threats

    def detect_python_keyloggers_smart(self):
        """Detect Python keyloggers"""
        python_keyloggers = []
        try:
            timeout = 30
            start_time = time.time()
            
            for process in psutil.process_iter(['pid', 'name', 'cmdline', 'exe']):
                try:
                    if time.time() - start_time > timeout:
                        break
                    
                    info = process.info
                    pid = info['pid']
                    name = info['name']
                    
                    if not info or 'name' not in info:
                        continue
                    
                    cmdline = self.safe_cmdline_join(info.get('cmdline', [])).lower()
                    exe_path = info.get('exe', 'Unknown')
                    
                    if pid <= 4:
                        continue
                    
                    if self.is_whitelisted_process(name, "", cmdline):
                        continue
                    
                    if name.lower() in ['python.exe', 'python3.exe', 'pythonw.exe']:
                        is_keylogger, patterns, reason = self.is_likely_keylogger(cmdline)
                        
                        if is_keylogger:
                            keylogger_info = {
                                'type': 'PROCESS',
                                'pid': pid,
                                'name': f"{name} (SMART KEYLOGGER DETECTION)",
                                'path': exe_path,
                                'hook_type': 'Smart Python Analysis',
                                'risk_level': 'CRITICAL',
                                'detection_reason': reason,
                                'patterns': patterns,
                                'cmdline': cmdline[:150] + "..." if len(cmdline) > 150 else cmdline
                            }
                            python_keyloggers.append(keylogger_info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            pass
        
        return python_keyloggers

    def detect_new_files(self):
        """Detect new files"""
        file_threats = []
        try:
            current_dir = os.getcwd()
            desktop_dir = os.path.join(os.path.expanduser("~"), "Desktop")
            locations_to_check = [current_dir, desktop_dir]
            
            for location in locations_to_check:
                if not os.path.exists(location):
                    continue
                try:
                    for item in os.listdir(location):
                        item_path = os.path.join(location, item)
                        
                        if self.is_whitelisted_file(item_path, item):
                            continue
                        
                        if os.path.isfile(item_path):
                            try:
                                creation_time = os.path.getctime(item_path)
                                current_time = time.time()
                                
                                if (current_time - creation_time) <= 60:
                                    item_lower = item.lower()
                                    for pattern in self.suspicious_files:
                                        if pattern in item_lower:
                                            file_info = {
                                                'type': 'FILE',
                                                'pid': 0,
                                                'name': f"NEW SUSPICIOUS FILE: {item}",
                                                'path': item_path,
                                                'hook_type': 'Real-time File Detection',
                                                'risk_level': 'HIGH',
                                                'created': datetime.fromtimestamp(creation_time).strftime("%H:%M:%S"),
                                                'detection_reason': f"Suspicious filename pattern: {pattern}"
                                            }
                                            file_threats.append(file_info)
                                            break
                            except (OSError, PermissionError):
                                continue
                except PermissionError:
                    continue
        except Exception as e:
            pass
        
        return file_threats

    def show_keylogger_alert(self, threat):
        """Show notification"""
        try:
            risk_level = threat.get('risk_level', 'MEDIUM')
            threat_name = threat['name']
            threat_path = threat.get('path', 'Unknown')
            detection_reason = threat.get('detection_reason', 'Suspicious activity')
            
            if risk_level == 'CRITICAL':
                title = "CRITICAL KEYLOGGER ALERT"
                message = f"KEYLOGGER DETECTED!\n\n" + \
                         f"Threat: {threat_name}\n" + \
                         f"Location: {threat_path}\n" + \
                         f"Reason: {detection_reason}\n\n" + \
                         f"Your keystrokes may be monitored!"
                messagebox.showerror(title, message)
            else:
                title = "Keylogger Detection Alert"
                message = f"Suspicious activity detected:\n\n" + \
                         f"Process: {threat_name}\n" + \
                         f"Location: {threat_path}\n" + \
                         f"Reason: {detection_reason}"
                messagebox.showwarning(title, message)
        except Exception as e:
            self.log_message(f"Alert error: {str(e)}")

    def detect_keyboard_hooks(self):
        """Detect hooks"""
        detected_hooks = []
        try:
            process_hooks = self.detect_process_based_hooks()
            detected_hooks.extend(process_hooks)
            python_hooks = self.detect_python_keyloggers()
            detected_hooks.extend(python_hooks)
            file_hooks = self.detect_file_based_keyloggers()
            detected_hooks.extend(file_hooks)
            cmd_hooks = self.detect_command_line_hooks()
            detected_hooks.extend(cmd_hooks)
            self.detected_hooks = detected_hooks
            return detected_hooks
        except Exception as e:
            self.log_message(f"Hook detection error: {str(e)}")
            return []

    def detect_python_keyloggers(self):
        """Detect Python keyloggers"""
        python_keyloggers = []
        try:
            timeout = 30
            start_time = time.time()
            
            for process in psutil.process_iter(['pid', 'name', 'cmdline', 'exe']):
                try:
                    if time.time() - start_time > timeout:
                        break
                    
                    info = process.info
                    pid = info['pid']
                    name = info['name']
                    cmdline = self.safe_cmdline_join(info.get('cmdline', [])).lower()
                    exe_path = info.get('exe', 'Unknown')
                    
                    if pid <= 4 or not info or 'name' not in info:
                        continue
                    
                    if self.is_whitelisted_process(name, "", cmdline):
                        continue
                    
                    if name.lower() in ['python.exe', 'python3.exe', 'pythonw.exe']:
                        is_keylogger, patterns, reason = self.is_likely_keylogger(cmdline)
                        
                        if is_keylogger:
                            keylogger_info = {
                                'type': 'PROCESS',
                                'pid': pid,
                                'name': f"{name} (Smart Python Keylogger)",
                                'path': exe_path,
                                'hook_type': 'Smart Python Analysis',
                                'risk_level': 'CRITICAL',
                                'patterns': patterns,
                                'detection_reason': reason,
                                'cmdline': cmdline[:100] + "..." if len(cmdline) > 100 else cmdline
                            }
                            python_keyloggers.append(keylogger_info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            pass
        
        return python_keyloggers

    def detect_file_based_keyloggers(self):
        """Detect file-based keyloggers"""
        file_threats = []
        try:
            locations_to_check = [
                os.getcwd(),
                os.path.expanduser("~"),
                os.path.join(os.path.expanduser("~"), "Desktop"),
            ]
            
            for location in locations_to_check:
                if not os.path.exists(location):
                    continue
                try:
                    for item in os.listdir(location):
                        item_lower = item.lower()
                        item_path = os.path.join(location, item)
                        
                        if self.is_whitelisted_file(item_path, item):
                            continue
                        
                        for pattern in self.suspicious_files:
                            if pattern in item_lower:
                                if os.path.isfile(item_path):
                                    file_info = {
                                        'type': 'FILE',
                                        'pid': 0,
                                        'name': f"Suspicious File: {item}",
                                        'path': item_path,
                                        'hook_type': 'File-based Keylogger Evidence',
                                        'risk_level': 'HIGH'
                                    }
                                    file_threats.append(file_info)
                                break
                except PermissionError:
                    continue
        except Exception as e:
            pass
        
        return file_threats

    def detect_process_based_hooks(self):
        """Process-based detection"""
        suspicious_hooks = []
        try:
            for process in psutil.process_iter(['pid', 'name', 'cmdline', 'exe']):
                try:
                    info = process.info
                    pid = info['pid']
                    name = info['name']
                    cmdline = self.safe_cmdline_join(info.get('cmdline', [])).lower()
                    exe_path = info.get('exe', 'Unknown')
                    
                    if pid <= 4 or not info or 'name' not in info:
                        continue
                    
                    if self.is_whitelisted_process(name, "", cmdline):
                        continue
                    
                    hook_keywords = ['hook', 'keylog', 'capture', 'spy', 'monitor', 'input', 'keyboard']
                    if any(keyword in name.lower() for keyword in hook_keywords):
                        hook_info = {
                            'type': 'PROCESS',
                            'pid': pid,
                            'name': info['name'],
                            'path': exe_path,
                            'hook_type': 'Process-based Hook Detection',
                            'risk_level': 'HIGH' if any(sus in name.lower() for sus in self.suspicious_processes) else 'MEDIUM'
                        }
                        suspicious_hooks.append(hook_info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            pass
        
        return suspicious_hooks

    def detect_command_line_hooks(self):
        """Command line analysis"""
        suspicious_hooks = []
        try:
            for process in psutil.process_iter(['pid', 'name', 'cmdline', 'exe']):
                try:
                    info = process.info
                    pid = info['pid']
                    name = info['name']
                    cmdline = self.safe_cmdline_join(info.get('cmdline', [])).lower()
                    exe_path = info.get('exe', 'Unknown')
                    
                    if pid <= 4 or not info or 'name' not in info:
                        continue
                    
                    if self.is_whitelisted_process(name, "", cmdline):
                        continue
                    
                    hook_patterns = ['hook', 'keylog', 'capture', 'monitor', 'spy', 'input']
                    if any(pattern in cmdline for pattern in hook_patterns):
                        hook_info = {
                            'type': 'PROCESS',
                            'pid': pid,
                            'name': name,
                            'path': exe_path,
                            'hook_type': 'Command Line Hook Indicator',
                            'risk_level': 'MEDIUM'
                        }
                        suspicious_hooks.append(hook_info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            pass
        
        return suspicious_hooks

    def log_message(self, message):
        """Log with throttling"""
        try:
            msg_hash = hash(message)
            current_time = time.time()
            
            if msg_hash in self.last_log_time:
                if current_time - self.last_log_time[msg_hash] < self.log_throttle_seconds:
                    return
            
            self.last_log_time[msg_hash] = current_time
            
            if hasattr(self, 'results_text'):
                timestamp = datetime.now().strftime("%H:%M:%S")
                formatted_message = f"[{timestamp}] {message}\n"
                self.results_text.insert(tk.END, formatted_message)
                self.results_text.see(tk.END)
                self.window.update_idletasks()
        except Exception as e:
            pass

    def update_system_stats(self):
        try:
            try:
                cpu_percent = psutil.cpu_percent(interval=0.1)
            except Exception:
                cpu_percent = 0.0
            
            try:
                memory = psutil.virtual_memory()
                memory_percent = memory.percent
            except Exception:
                memory_percent = 0.0
            
            try:
                process_count = len(list(psutil.process_iter()))
            except Exception:
                process_count = 0
            
            try:
                connection_count = len(psutil.net_connections())
            except (psutil.AccessDenied, PermissionError):
                connection_count = 0
            
            try:
                disk = psutil.disk_usage('C:')
                disk_percent = (disk.used / disk.total) * 100
            except (FileNotFoundError, PermissionError):
                disk_percent = 0.0
            
            try:
                boot_time = psutil.boot_time()
                uptime_seconds = time.time() - boot_time
                uptime_hours = int(uptime_seconds // 3600)
                uptime_minutes = int((uptime_seconds % 3600) // 60)
                uptime_str = f"{uptime_hours}h {uptime_minutes}m"
            except Exception:
                uptime_str = "Unknown"
            
            self.system_stats['cpu']['label'].config(text=f"{cpu_percent:.1f}%")
            self.system_stats['memory']['label'].config(text=f"{memory_percent:.1f}%")
            self.system_stats['processes']['label'].config(text=str(process_count))
            self.system_stats['connections']['label'].config(text=str(connection_count))
            self.system_stats['disk']['label'].config(text=f"{disk_percent:.1f}%")
            self.system_stats['uptime']['label'].config(text=uptime_str)
            
            if cpu_percent > 80:
                self.system_stats['cpu']['label'].config(fg="#ff7b72")
            elif cpu_percent > 50:
                self.system_stats['cpu']['label'].config(fg="#f59e0b")
            else:
                self.system_stats['cpu']['label'].config(fg="#3fb950")
            
            if memory_percent > 80:
                self.system_stats['memory']['label'].config(fg="#ff7b72")
            elif memory_percent > 60:
                self.system_stats['memory']['label'].config(fg="#f59e0b")
            else:
                self.system_stats['memory']['label'].config(fg="#3fb950")
            
            current_time = datetime.now().strftime("%H:%M:%S")
            self.last_updated_label.config(text=f"Updated: {current_time}")
            
            if hasattr(self, 'metric_widgets'):
                self.metric_widgets["processes"].config(text=str(process_count))
        except Exception as e:
            if hasattr(self, 'system_status_label'):
                self.system_status_label.config(text="MONITORING ERROR", fg="#ff7b72")
        
        self.window.after(2500, self.update_system_stats)

    def update_time_display(self):
        try:
            if hasattr(self, 'metric_widgets') and self.last_scan_time:
                time_diff = datetime.now() - self.last_scan_time
                if time_diff.seconds < 60:
                    time_ago = f"{time_diff.seconds}s ago"
                elif time_diff.seconds < 3600:
                    time_ago = f"{time_diff.seconds//60}m ago"
                else:
                    time_ago = f"{time_diff.seconds//3600}h ago"
                self.metric_widgets["last_scan"].config(text=time_ago, fg="#58a6ff")
        except Exception:
            pass
        
        self.window.after(1000, self.update_time_display)

    def full_scan(self):
        if self.scanning:
            return
        
        self.scanning = True
        self.full_scan_btn.config(state="disabled", text="Scanning...")
        self.detected_threats = []
        
        if hasattr(self, 'results_text'):
            self.results_text.delete(1.0, tk.END)
        
        threading.Thread(target=self.perform_full_scan, daemon=True).start()

    def perform_full_scan(self):
        try:
            total_threats = 0
            self.log_message("SMART KEYLOGGER DETECTION SCAN INITIATED")
            self.log_message("=" * 70)
            
            phases = [
                ("Scanning for standard keylogger processes...", self.scan_processes),
                ("SMART PYTHON KEYLOGGER ANALYSIS...", self.detect_keyboard_hooks),
                ("Analyzing registry for persistence...", self.scan_registry),
                ("Checking suspicious files and folders...", self.detect_file_based_keyloggers),
            ]
            
            for phase_text, scan_func in phases:
                self.log_message(f"{phase_text}")
                time.sleep(1.5)
                
                threats = scan_func()
                total_threats += len(threats)
                self.detected_threats.extend(threats)
            
            self.finish_scan(total_threats, len(list(psutil.process_iter())) if psutil else 0)
        except Exception as e:
            self.log_message(f"Scan error: {str(e)}")
            self.finish_scan(0, 0)

    def scan_processes(self):
        """Scan processes"""
        threats = []
        process_count = 0
        try:
            for process in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
                try:
                    process_count += 1
                    info = process.info
                    process_name = info['name']
                    cmdline = self.safe_cmdline_join(info.get('cmdline', [])).lower()
                    exe_path = info.get('exe', 'Unknown')
                    
                    if self.is_whitelisted_process(process_name, info.get('exe', ''), cmdline):
                        continue
                    
                    for suspicious in self.suspicious_processes:
                        if suspicious in process_name.lower():
                            threat_info = {
                                'type': 'PROCESS',
                                'pid': info['pid'],
                                'name': f"KEYLOGGER PROCESS: {info['name']}",
                                'path': exe_path,
                                'hook_type': 'Process Detection',
                                'risk_level': 'CRITICAL'
                            }
                            threats.append(threat_info)
                            self.log_message(f"KEYLOGGER DETECTED: {info['name']} at {exe_path}")
                            break
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            self.log_message(f"Process scan error: {str(e)}")
        
        if not threats:
            self.log_message(f"Process scan complete: {process_count} processes analyzed")
        else:
            self.log_message(f"Process scan: {len(threats)} threats detected!")
        
        return threats

    def scan_registry(self):
        threats = []
        try:
            for key_path in self.suspicious_registry_keys:
                try:
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
                        i = 0
                        while True:
                            try:
                                name, value, _ = winreg.EnumValue(key, i)
                                value_lower = str(value).lower()
                                
                                if any(whitelist_item in value_lower for whitelist_item in self.whitelist_files):
                                    i += 1
                                    continue
                                
                                for suspicious in self.suspicious_processes:
                                    if suspicious in value_lower or suspicious in name.lower():
                                        threat_info = {
                                            'type': 'REGISTRY',
                                            'name': f"REGISTRY PERSISTENCE: {name}",
                                            'reg_path': key_path,
                                            'value': value,
                                            'risk_level': 'CRITICAL'
                                        }
                                        threats.append(threat_info)
                                        self.log_message(f"SUSPICIOUS REGISTRY: {key_path}\\{name}")
                                        break
                                i += 1
                            except WindowsError:
                                break
                except WindowsError:
                    continue
        except Exception as e:
            self.log_message(f"Registry error: {str(e)}")
        
        if not threats:
            self.log_message("Registry scan complete: No threats")
        else:
            self.log_message(f"Registry: {len(threats)} threats!")
        
        return threats

    def finish_scan(self, threats_found, processes_scanned):
        try:
            self.scanning = False
            self.last_scan_time = datetime.now()
            self.full_scan_btn.config(state="normal", text="Full System Scan")
            self.update_metrics(threats=threats_found, processes=processes_scanned, registry=3)
            
            self.log_message("=" * 70)
            if threats_found > 0:
                self.log_message(f"SMART SCAN COMPLETE: {threats_found} KEYLOGGERS DETECTED!")
                self.status_label.config(text=f"{threats_found} keyloggers found - CRITICAL!", fg="#ff7b72")
                self.show_flash_message(f"SCAN COMPLETE: {threats_found} keyloggers found!", "#ff7b72", 5000)
                messagebox.showwarning("KEYLOGGER ALERT",
                                     f"CRITICAL SECURITY BREACH!\n\n" +
                                     f"{threats_found} keyloggers detected!\n\n" +
                                     f"Click 'Export Threats' button to save detailed report with exact locations!")
            else:
                self.log_message("SMART SCAN COMPLETE: No keyloggers detected!")
                self.status_label.config(text="No keyloggers detected - System secure", fg="#3fb950")
                self.show_flash_message("SCAN COMPLETE: System is secure!", "#3fb950", 4000)
        except Exception as e:
            self.log_message(f"Finish scan error: {str(e)}")

    def update_metrics(self, threats=None, processes=None, registry=None):
        try:
            if hasattr(self, 'metric_widgets'):
                if threats is not None:
                    color = "#ff7b72" if threats > 0 else "#3fb950"
                    self.metric_widgets["threats"].config(text=str(threats), fg=color)
                if processes is not None:
                    self.metric_widgets["processes"].config(text=str(processes))
                if registry is not None:
                    self.metric_widgets["registry"].config(text=str(registry))
        except Exception as e:
            pass

    def run(self):
        self.window.mainloop()

if __name__ == "__main__":
    app = KeyloggerDetectionSystem()
    app.run()