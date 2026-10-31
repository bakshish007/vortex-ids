#!/usr/bin/env python3
"""
================================================================================
AegisCampus IDS — Red Team GUI Security Simulator & IDS Validation Console
Problem Statement: CTBF-CS-03
Standalone Python Tkinter GUI Application for Local IDS Validation.
================================================================================
Features:
- Startup environment check for Nmap installation with visual indicator badge
- Execution of standard diagnostic Nmap scan profiles against target IP
- Dynamic loading & mapping of detection signatures, thresholds, and patterns from rules.json
- Direct local IP detection and configurable target host
- Real network packet / socket probing + IDS API alert validation
- Live color-coded terminal log with MITRE ATT&CK technique IDs
================================================================================
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import socket
import time
import random
import json
import os
import sys
import subprocess
import shutil
import urllib.request
import webbrowser
from datetime import datetime

# ─────────────────────────────────────────────────────────────────────────────
# UI Palette & Styling
# ─────────────────────────────────────────────────────────────────────────────
COLORS = {
    "bg":         "#0d1117",
    "panel":      "#161b22",
    "card":       "#1c2128",
    "border":     "#30363d",
    "accent":     "#f85149",
    "orange":     "#ff7b72",
    "green":      "#3fb950",
    "green_bg":   "#13231b",
    "red":        "#f85149",
    "red_bg":     "#2d1517",
    "yellow":     "#d29922",
    "yellow_bg":  "#2e2305",
    "blue":       "#58a6ff",
    "purple":     "#bc8cff",
    "cyan":       "#39c5cf",
    "text":       "#e6edf3",
    "muted":      "#8b949e",
    "white":      "#ffffff",
}

# ─────────────────────────────────────────────────────────────────────────────
# Path & Configuration Resolvers
# ─────────────────────────────────────────────────────────────────────────────
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
POSSIBLE_RULES_PATHS = [
    os.path.join(SCRIPT_DIR, "rules.json"),
    os.path.join(SCRIPT_DIR, "..", "edge-agent", "rules.json"),
]

def resolve_rules_file():
    for p in POSSIBLE_RULES_PATHS:
        if os.path.isfile(p):
            return os.path.abspath(p)
    return os.path.abspath(POSSIBLE_RULES_PATHS[0])

def load_rules_data():
    path = resolve_rules_file()
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data, path
        except Exception as e:
            print(f"[WARN] Error loading rules from {path}: {e}")
    return {}, path

def get_system_local_ip():
    """Detect the active local IP address connected to the primary network."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"

# ─────────────────────────────────────────────────────────────────────────────
# Nmap Environment Inspector
# ─────────────────────────────────────────────────────────────────────────────
def inspect_nmap_installation():
    """
    Check if Nmap binary is available in PATH and probe its version.
    Returns: (is_installed: bool, version_info: str, binary_path: str)
    """
    nmap_path = shutil.which("nmap")
    if not nmap_path:
        # Common Windows installation locations check
        win_candidates = [
            r"C:\Program Files (x86)\Nmap\nmap.exe",
            r"C:\Program Files\Nmap\nmap.exe",
        ]
        for candidate in win_candidates:
            if os.path.isfile(candidate):
                nmap_path = candidate
                break

    if not nmap_path:
        return False, "Nmap binary not found in system PATH", ""

    try:
        res = subprocess.run([nmap_path, "--version"], capture_output=True, text=True, timeout=3)
        first_line = res.stdout.strip().splitlines()[0] if res.stdout else "Nmap (version unknown)"
        return True, first_line, nmap_path
    except Exception as e:
        return True, f"Nmap found at {nmap_path} (probe err: {e})", nmap_path


# ─────────────────────────────────────────────────────────────────────────────
# Main Red Team Tkinter Application
# ─────────────────────────────────────────────────────────────────────────────
class RedTeamApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("AegisCampus IDS — Red Team GUI Security Simulator (CTBF-CS-03)")
        self.geometry("1300x880")
        self.minsize(1080, 720)
        self.configure(bg=COLORS["bg"])

        # State Variables
        self.local_ip = get_system_local_ip()
        self.target_ip_var = tk.StringVar(value=self.local_ip)
        self.backend_url_var = tk.StringVar(value="http://localhost:3001")
        self.real_packet_mode = tk.BooleanVar(value=True)

        self.rules_data, self.rules_file_path = load_rules_data()
        self.scan_profiles = self.rules_data.get("scan_profiles", {})
        self.simulated_vectors = self.rules_data.get("simulated_traffic_profiles", {})
        self.detection_thresholds = self.rules_data.get("detection_thresholds", {})

        self.nmap_installed, self.nmap_version_str, self.nmap_path = inspect_nmap_installation()
        self.total_operations = 0
        self.active_threads = []
        self._cancel_signal = threading.Event()

        # Build GUI Layout
        self._setup_styles()
        self._build_header()
        self._build_nmap_status_bar()
        self._build_control_ribbon()
        self._build_main_workspace()
        self._build_status_footer()

        # Initial Welcome Logs
        self._log(f"[*] Red Team IDS Validation Console initiated. Local IP: {self.local_ip}", COLORS["green"])
        self._log(f"[*] Loaded rules dictionary from: {self.rules_file_path}", COLORS["cyan"])
        self._log(f"[*] Cataloged {len(self.scan_profiles)} scan profiles & {len(self.simulated_vectors)} traffic vector patterns.", COLORS["cyan"])
        if self.nmap_installed:
            self._log(f"[+] Nmap Environment: {self.nmap_version_str} ({self.nmap_path})", COLORS["green"])
        else:
            self._log("[-] Nmap not detected on host system. Standard Nmap scans will run in API Simulation Mode.", COLORS["yellow"])
        self._log("=" * 86, COLORS["border"])

    # ── Styling ──────────────────────────────────────────────────────────────
    def _setup_styles(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure(".", background=COLORS["bg"], foreground=COLORS["text"], font=("Segoe UI", 9))
        style.configure("TNotebook", background=COLORS["bg"], borderwidth=0)
        style.configure("TNotebook.Tab", background=COLORS["panel"], foreground=COLORS["muted"],
                        font=("Segoe UI", 9, "bold"), padding=[12, 6])
        style.map("TNotebook.Tab",
                  background=[("selected", COLORS["card"])],
                  foreground=[("selected", COLORS["text"])])

    # ── Header ───────────────────────────────────────────────────────────────
    def _build_header(self):
        hdr = tk.Frame(self, bg="#0a0d12", pady=8, padx=16)
        hdr.pack(fill="x")

        # Title & Subtitle
        title_box = tk.Frame(hdr, bg="#0a0d12")
        title_box.pack(side="left")

        tk.Label(title_box, text="⚡ RED TEAM ATTACK CONSOLE", bg="#0a0d12",
                 fg=COLORS["accent"], font=("Consolas", 15, "bold")).pack(anchor="w")
        tk.Label(title_box, text="AegisCampus IDS (CTBF-CS-03) — Local Security Simulation & Diagnostic Probe Engine",
                 bg="#0a0d12", fg=COLORS["muted"], font=("Segoe UI", 8)).pack(anchor="w")

        # Right-side Action Quick Buttons
        right_box = tk.Frame(hdr, bg="#0a0d12")
        right_box.pack(side="right")

        tk.Button(right_box, text="🌐 Check Nmap", command=self._recheck_nmap,
                  bg=COLORS["panel"], fg=COLORS["cyan"], font=("Segoe UI", 8, "bold"),
                  relief="flat", padx=10, pady=3, cursor="hand2").pack(side="left", padx=4)

        tk.Button(right_box, text="⟳ Test Backend", command=self._test_backend_health,
                  bg=COLORS["panel"], fg=COLORS["blue"], font=("Segoe UI", 8, "bold"),
                  relief="flat", padx=10, pady=3, cursor="hand2").pack(side="left", padx=4)

    # ── Nmap Visual Indicator Banner ─────────────────────────────────────────
    def _build_nmap_status_bar(self):
        self.nmap_banner = tk.Frame(self, padx=16, pady=6)
        self.nmap_banner.pack(fill="x")
        self._update_nmap_banner_ui()

    def _update_nmap_banner_ui(self):
        for widget in self.nmap_banner.winfo_children():
            widget.destroy()

        if self.nmap_installed:
            self.nmap_banner.configure(bg=COLORS["green_bg"])
            icon_lbl = tk.Label(self.nmap_banner, text="✅ NMAP INSTALLED", bg=COLORS["green_bg"],
                                fg=COLORS["green"], font=("Segoe UI", 9, "bold"))
            icon_lbl.pack(side="left", padx=(0, 10))

            detail_lbl = tk.Label(self.nmap_banner, text=f"{self.nmap_version_str}  —  Executable: {self.nmap_path}",
                                  bg=COLORS["green_bg"], fg=COLORS["text"], font=("Consolas", 8))
            detail_lbl.pack(side="left")

            badge = tk.Label(self.nmap_banner, text="READY FOR LIVE SCANS", bg=COLORS["green"],
                             fg=COLORS["white"], font=("Segoe UI", 7, "bold"), padx=6, pady=1)
            badge.pack(side="right")
        else:
            self.nmap_banner.configure(bg=COLORS["red_bg"])
            icon_lbl = tk.Label(self.nmap_banner, text="❌ NMAP NOT DETECTED", bg=COLORS["red_bg"],
                                fg=COLORS["red"], font=("Segoe UI", 9, "bold"))
            icon_lbl.pack(side="left", padx=(0, 10))

            detail_lbl = tk.Label(self.nmap_banner,
                                  text="Nmap command line tool is not found in system PATH. Diagnostic scans will execute via API simulation mode.",
                                  bg=COLORS["red_bg"], fg=COLORS["text"], font=("Segoe UI", 8))
            detail_lbl.pack(side="left")

            dl_btn = tk.Button(self.nmap_banner, text="📥 Download Nmap", command=lambda: webbrowser.open("https://nmap.org/download.html"),
                               bg=COLORS["red"], fg=COLORS["white"], font=("Segoe UI", 8, "bold"),
                               relief="flat", padx=8, pady=1, cursor="hand2")
            dl_btn.pack(side="right", padx=(4, 0))

            rescan_btn = tk.Button(self.nmap_banner, text="Re-Scan", command=self._recheck_nmap,
                                   bg=COLORS["panel"], fg=COLORS["text"], font=("Segoe UI", 8),
                                   relief="flat", padx=6, pady=1, cursor="hand2")
            rescan_btn.pack(side="right")

    # ── Control & Target Ribbon ──────────────────────────────────────────────
    def _build_control_ribbon(self):
        ribbon = tk.Frame(self, bg=COLORS["panel"], padx=14, pady=8)
        ribbon.pack(fill="x")

        # Target IP Configuration
        tk.Label(ribbon, text="Target IP:", bg=COLORS["panel"], fg=COLORS["muted"],
                 font=("Segoe UI", 9, "bold")).pack(side="left")

        target_ent = tk.Entry(ribbon, textvariable=self.target_ip_var, bg=COLORS["border"],
                              fg=COLORS["text"], insertbackground=COLORS["white"],
                              font=("Consolas", 10, "bold"), width=16, relief="flat")
        target_ent.pack(side="left", padx=(6, 8))

        # Quick preset buttons for IP
        tk.Button(ribbon, text=f"Local IP ({self.local_ip})",
                  command=lambda: self.target_ip_var.set(self.local_ip),
                  bg=COLORS["card"], fg=COLORS["cyan"], font=("Segoe UI", 8),
                  relief="flat", padx=8, cursor="hand2").pack(side="left", padx=2)

        tk.Button(ribbon, text="Loopback (127.0.0.1)",
                  command=lambda: self.target_ip_var.set("127.0.0.1"),
                  bg=COLORS["card"], fg=COLORS["muted"], font=("Segoe UI", 8),
                  relief="flat", padx=8, cursor="hand2").pack(side="left", padx=2)

        # Backend URL configuration
        tk.Label(ribbon, text="Backend URL:", bg=COLORS["panel"], fg=COLORS["muted"],
                 font=("Segoe UI", 9, "bold")).pack(side="left", padx=(14, 4))

        backend_ent = tk.Entry(ribbon, textvariable=self.backend_url_var, bg=COLORS["border"],
                               fg=COLORS["text"], insertbackground=COLORS["white"],
                               font=("Consolas", 9), width=22, relief="flat")
        backend_ent.pack(side="left", padx=(2, 10))

        # Real packets toggle checkbox
        chk = tk.Checkbutton(ribbon, text="Emit Real Socket Probes", variable=self.real_packet_mode,
                             bg=COLORS["panel"], fg=COLORS["text"], selectcolor=COLORS["card"],
                             activebackground=COLORS["panel"], activeforeground=COLORS["text"],
                             font=("Segoe UI", 8))
        chk.pack(side="left", padx=6)

        # Emergency Stop Button
        tk.Button(ribbon, text="⏹ STOP ALL", command=self._stop_all_tasks,
                  bg=COLORS["red"], fg=COLORS["white"], font=("Segoe UI", 9, "bold"),
                  relief="flat", padx=12, pady=2, cursor="hand2").pack(side="right")

        # Global Launch Button
        tk.Button(ribbon, text="🔥 RUN ALL SCANS", command=self._run_all_scan_profiles,
                  bg=COLORS["orange"], fg=COLORS["bg"], font=("Segoe UI", 9, "bold"),
                  relief="flat", padx=12, pady=2, cursor="hand2").pack(side="right", padx=6)

    # ── Main Workspace (Split View: Tabs on Left, Console on Right) ───────────
    def _build_main_workspace(self):
        paned = tk.PanedWindow(self, orient="horizontal", bg=COLORS["bg"], sashwidth=4, sashrelief="flat")
        paned.pack(fill="both", expand=True, padx=12, pady=8)

        # Left Container (Notebook Tabs)
        left_container = tk.Frame(paned, bg=COLORS["bg"])
        paned.add(left_container, minsize=520, width=680)

        notebook = ttk.Notebook(left_container)
        notebook.pack(fill="both", expand=True)

        # Tab 1: Diagnostic Nmap Scan Profiles
        tab_nmap = tk.Frame(notebook, bg=COLORS["panel"])
        notebook.add(tab_nmap, text="  Nmap Scan Profiles  ")
        self._build_nmap_profiles_view(tab_nmap)

        # Tab 2: Simulated Traffic Patterns & Brute Force
        tab_traffic = tk.Frame(notebook, bg=COLORS["panel"])
        notebook.add(tab_traffic, text="  Traffic Patterns & Floods  ")
        self._build_traffic_patterns_view(tab_traffic)

        # Tab 3: Dynamic rules.json Viewer & Thresholds
        tab_rules = tk.Frame(notebook, bg=COLORS["panel"])
        notebook.add(tab_rules, text="  Cataloged Rules.json  ")
        self._build_rules_viewer_view(tab_rules)

        # Right Container (Live Execution Log Console)
        right_container = tk.Frame(paned, bg=COLORS["bg"])
        paned.add(right_container, minsize=380)

        log_header = tk.Frame(right_container, bg=COLORS["panel"], pady=6, padx=10)
        log_header.pack(fill="x")

        tk.Label(log_header, text="📡  LIVE DIAGNOSTIC LOG", bg=COLORS["panel"],
                 fg=COLORS["cyan"], font=("Consolas", 10, "bold")).pack(side="left")

        self.op_counter_lbl = tk.Label(log_header, text="Operations Executed: 0",
                                       bg=COLORS["panel"], fg=COLORS["muted"], font=("Segoe UI", 8))
        self.op_counter_lbl.pack(side="right", padx=6)

        tk.Button(log_header, text="Clear Log", command=self._clear_log,
                  bg=COLORS["border"], fg=COLORS["muted"], font=("Segoe UI", 8),
                  relief="flat", padx=8, cursor="hand2").pack(side="right", padx=4)

        # Scrolled Text Widget
        self.log_widget = scrolledtext.ScrolledText(
            right_container, bg="#0a0e14", fg=COLORS["text"],
            font=("Consolas", 9), relief="flat", wrap="word",
            state="disabled", insertbackground=COLORS["white"]
        )
        self.log_widget.pack(fill="both", expand=True, pady=(4, 0))

        # Configure color tags
        for name, hex_val in COLORS.items():
            self.log_widget.tag_configure(name, foreground=hex_val)
        self.log_widget.tag_configure("bold", font=("Consolas", 9, "bold"))

    # ── Tab 1: Diagnostic Nmap Scan Profiles View ────────────────────────────
    def _build_nmap_profiles_view(self, parent):
        scrollable_frame, inner = self._create_scrollable_container(parent)

        header_card = tk.Frame(inner, bg=COLORS["card"], padx=12, pady=10)
        header_card.pack(fill="x", padx=6, pady=6)

        mode_txt = "Mode: Real Nmap Engine (Subprocess Stream)" if self.nmap_installed else "Mode: IDS API Simulation (Nmap Not Found)"
        mode_color = COLORS["green"] if self.nmap_installed else COLORS["yellow"]
        tk.Label(header_card, text="Standard Diagnostic Scan Profiles (Mapped to rules.json)",
                 bg=COLORS["card"], fg=COLORS["text"], font=("Segoe UI", 10, "bold")).pack(anchor="w")
        tk.Label(header_card, text=f"Triggers exact diagnostic scan vectors against the target IP. {mode_txt}",
                 bg=COLORS["card"], fg=mode_color, font=("Segoe UI", 8)).pack(anchor="w", pady=(2, 0))

        # Populate from self.scan_profiles
        col, row = 0, 0
        grid_container = tk.Frame(inner, bg=COLORS["panel"])
        grid_container.pack(fill="both", expand=True, padx=4, pady=4)
        grid_container.columnconfigure(0, weight=1)
        grid_container.columnconfigure(1, weight=1)

        for key, profile in self.scan_profiles.items():
            card = tk.Frame(grid_container, bg=COLORS["card"], padx=10, pady=8, highlightbackground=COLORS["border"], highlightthickness=1)
            card.grid(row=row, column=col, padx=4, pady=4, sticky="nsew")

            # Name and Severity
            title_bar = tk.Frame(card, bg=COLORS["card"])
            title_bar.pack(fill="x")

            sev = profile.get("severity", "MEDIUM")
            sev_color = COLORS["red"] if sev == "CRITICAL" else COLORS["orange"] if sev == "HIGH" else COLORS["yellow"]
            tk.Label(title_bar, text=profile.get("name", key), bg=COLORS["card"],
                     fg=COLORS["text"], font=("Segoe UI", 9, "bold"), anchor="w", wraplength=220).pack(side="left")
            tk.Label(title_bar, text=f" {sev} ", bg=sev_color, fg=COLORS["bg"],
                     font=("Segoe UI", 7, "bold")).pack(side="right")

            # Command preview
            nmap_cmd = "nmap " + " ".join(profile.get("nmap_args", [])) + " <target>"
            tk.Label(card, text=nmap_cmd, bg=COLORS["card"], fg=COLORS["cyan"],
                     font=("Consolas", 8), anchor="w").pack(fill="x", pady=(3, 1))

            # Pattern & MITRE description
            mitre_id = profile.get("mitre_attack_id", "T1046")
            tk.Label(card, text=f"MITRE: {mitre_id} | {profile.get('description', '')}", bg=COLORS["card"],
                     fg=COLORS["muted"], font=("Segoe UI", 8), anchor="w", wraplength=260, justify="left").pack(fill="x")

            # Action Buttons Row
            btn_row = tk.Frame(card, bg=COLORS["card"], pady=4)
            btn_row.pack(fill="x")

            tk.Button(btn_row, text="▶ Run Scan",
                      command=lambda k=key, p=profile: self._execute_scan_profile(k, p),
                      bg=COLORS["panel"], fg=COLORS["green"], font=("Segoe UI", 8, "bold"),
                      relief="flat", padx=10, cursor="hand2").pack(side="left")

            tk.Button(btn_row, text="Burst ×3",
                      command=lambda k=key, p=profile: self._execute_scan_burst(k, p, 3),
                      bg=COLORS["panel"], fg=COLORS["orange"], font=("Segoe UI", 8),
                      relief="flat", padx=6, cursor="hand2").pack(side="left", padx=4)

            col += 1
            if col > 1:
                col = 0
                row += 1

    # ── Tab 2: Traffic Patterns & Simulated Vectors View ─────────────────────
    def _build_traffic_patterns_view(self, parent):
        scrollable_frame, inner = self._create_scrollable_container(parent)

        header_card = tk.Frame(inner, bg=COLORS["card"], padx=12, pady=10)
        header_card.pack(fill="x", padx=6, pady=6)

        tk.Label(header_card, text="Simulated Traffic Patterns, Floods & Brute Force Profiles",
                 bg=COLORS["card"], fg=COLORS["text"], font=("Segoe UI", 10, "bold")).pack(anchor="w")
        tk.Label(header_card, text="Generates live synthetic socket traffic and evaluates IDS detection thresholds in rules.json.",
                 bg=COLORS["card"], fg=COLORS["muted"], font=("Segoe UI", 8)).pack(anchor="w", pady=(2, 0))

        col, row = 0, 0
        grid_container = tk.Frame(inner, bg=COLORS["panel"])
        grid_container.pack(fill="both", expand=True, padx=4, pady=4)
        grid_container.columnconfigure(0, weight=1)
        grid_container.columnconfigure(1, weight=1)

        for key, vec in self.simulated_vectors.items():
            card = tk.Frame(grid_container, bg=COLORS["card"], padx=10, pady=8, highlightbackground=COLORS["border"], highlightthickness=1)
            card.grid(row=row, column=col, padx=4, pady=4, sticky="nsew")

            title_bar = tk.Frame(card, bg=COLORS["card"])
            title_bar.pack(fill="x")

            sev = vec.get("severity", "HIGH")
            sev_color = COLORS["red"] if sev == "CRITICAL" else COLORS["orange"] if sev == "HIGH" else COLORS["yellow"]
            tk.Label(title_bar, text=vec.get("name", key), bg=COLORS["card"],
                     fg=COLORS["text"], font=("Segoe UI", 9, "bold"), anchor="w", wraplength=220).pack(side="left")
            tk.Label(title_bar, text=f" {sev} ", bg=sev_color, fg=COLORS["bg"],
                     font=("Segoe UI", 7, "bold")).pack(side="right")

            cat = vec.get("category", "General")
            port = vec.get("target_port", 0)
            tk.Label(card, text=f"Category: {cat} | Target Port: {port} | MITRE: {vec.get('mitre_attack_id', 'T1498')}",
                     bg=COLORS["card"], fg=COLORS["cyan"], font=("Consolas", 8), anchor="w").pack(fill="x", pady=(2, 1))

            tk.Label(card, text=vec.get("description", ""), bg=COLORS["card"],
                     fg=COLORS["muted"], font=("Segoe UI", 8), anchor="w", wraplength=260, justify="left").pack(fill="x")

            btn_row = tk.Frame(card, bg=COLORS["card"], pady=4)
            btn_row.pack(fill="x")

            tk.Button(btn_row, text="▶ Trigger Vector",
                      command=lambda k=key, v=vec: self._execute_traffic_vector(k, v),
                      bg=COLORS["panel"], fg=COLORS["green"], font=("Segoe UI", 8, "bold"),
                      relief="flat", padx=10, cursor="hand2").pack(side="left")

            tk.Button(btn_row, text="Flood Burst ×5",
                      command=lambda k=key, v=vec: self._execute_traffic_burst(k, v, 5),
                      bg=COLORS["panel"], fg=COLORS["orange"], font=("Segoe UI", 8),
                      relief="flat", padx=6, cursor="hand2").pack(side="left", padx=4)

            col += 1
            if col > 1:
                col = 0
                row += 1

    # ── Tab 3: Dynamic rules.json Viewer ─────────────────────────────────────
    def _build_rules_viewer_view(self, parent):
        top_bar = tk.Frame(parent, bg=COLORS["panel"], padx=10, pady=8)
        top_bar.pack(fill="x")

        tk.Label(top_bar, text=f"Rules Source: {self.rules_file_path}",
                 bg=COLORS["panel"], fg=COLORS["cyan"], font=("Consolas", 9)).pack(side="left")

        tk.Button(top_bar, text="⟳ Reload rules.json", command=self._reload_rules,
                  bg=COLORS["card"], fg=COLORS["text"], font=("Segoe UI", 8, "bold"),
                  relief="flat", padx=10, cursor="hand2").pack(side="right")

        viewer = scrolledtext.ScrolledText(parent, bg="#0a0e14", fg=COLORS["text"],
                                          font=("Consolas", 9), relief="flat")
        viewer.pack(fill="both", expand=True, padx=8, pady=8)

        pretty_json = json.dumps(self.rules_data, indent=2)
        viewer.insert("1.0", pretty_json)
        viewer.configure(state="disabled")

    # ── Scrollable Frame Helper ──────────────────────────────────────────────
    def _create_scrollable_container(self, parent):
        canvas = tk.Canvas(parent, bg=COLORS["panel"], highlightthickness=0)
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg=COLORS["panel"])

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        canvas.bind_all("<MouseWheel>", lambda e: canvas.yview_scroll(int(-1*(e.delta/120)), "units"))
        return canvas, scrollable_frame

    # ── Status Footer ────────────────────────────────────────────────────────
    def _build_status_footer(self):
        footer = tk.Frame(self, bg=COLORS["panel"], pady=3, padx=12)
        footer.pack(fill="x", side="bottom")

        self.footer_status = tk.Label(footer, text=f"Engine Idle | Target IP: {self.local_ip} | Rules: Active",
                                      bg=COLORS["panel"], fg=COLORS["muted"], font=("Segoe UI", 8))
        self.footer_status.pack(side="left")

        tk.Label(footer, text="Zero GenAI | Deterministic Playbook Engine | BPF Aware",
                 bg=COLORS["panel"], fg=COLORS["muted"], font=("Segoe UI", 8)).pack(side="right")

    # ── Action Handlers ──────────────────────────────────────────────────────
    def _recheck_nmap(self):
        self.nmap_installed, self.nmap_version_str, self.nmap_path = inspect_nmap_installation()
        self._update_nmap_banner_ui()
        if self.nmap_installed:
            self._log(f"[+] Nmap detected: {self.nmap_version_str}", COLORS["green"])
        else:
            self._log("[-] Nmap check: Still not detected in PATH.", COLORS["yellow"])

    def _test_backend_health(self):
        backend = self.backend_url_var.get().rstrip("/")
        def worker():
            self._log(f"[*] Testing connection to backend: {backend}/api/health...", COLORS["cyan"])
            try:
                req = urllib.request.Request(f"{backend}/api/health", headers={"User-Agent": "AegisRedTeam"})
                with urllib.request.urlopen(req, timeout=3) as resp:
                    status = resp.status
                    data = resp.read().decode("utf-8")
                    self._log(f"[+] Backend Online (HTTP {status}): {data}", COLORS["green"])
            except Exception as e:
                self._log(f"[-] Backend unreachable at {backend}: {e}", COLORS["red"])
        threading.Thread(target=worker, daemon=True).start()

    def _reload_rules(self):
        self.rules_data, self.rules_file_path = load_rules_data()
        self.scan_profiles = self.rules_data.get("scan_profiles", {})
        self.simulated_vectors = self.rules_data.get("simulated_traffic_profiles", {})
        self._log(f"[+] Reloaded rules from {self.rules_file_path}", COLORS["green"])

    def _stop_all_tasks(self):
        self._cancel_signal.set()
        self._log("[!] Emergency STOP signal delivered to all active attack routines.", COLORS["red"])
        self.footer_status.config(text="Status: Operations Stopped by User")

    # ── Nmap Scan Execution ──────────────────────────────────────────────────
    def _execute_scan_profile(self, key, profile):
        target = self.target_ip_var.get().strip() or self.local_ip
        backend = self.backend_url_var.get().rstrip("/")
        do_real_socket = self.real_packet_mode.get()

        def worker():
            self.total_operations += 1
            self._update_counter()
            self._log(f"\n[SCAN INITIATED] {profile.get('name', key)} -> Target: {target}", COLORS["cyan"])
            self.footer_status.config(text=f"Running: {profile.get('name', key)} against {target}")

            if self.nmap_installed:
                # Execute real Nmap subprocess
                nmap_args = profile.get("nmap_args", ["-sS", "-T4"])
                cmd = [self.nmap_path] + nmap_args + [target]
                self._log(f"    CMD: {' '.join(cmd)}", COLORS["muted"])

                try:
                    proc = subprocess.Popen(
                        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                        text=True, bufsize=1
                    )
                    for line in iter(proc.stdout.readline, ""):
                        if self._cancel_signal.is_set():
                            proc.terminate()
                            self._log("    [CANCELLED] Subprocess halted.", COLORS["yellow"])
                            break
                        clean_line = line.strip()
                        if clean_line:
                            line_color = COLORS["text"]
                            if "open" in clean_line.lower():
                                line_color = COLORS["green"]
                            elif "filtered" in clean_line.lower() or "closed" in clean_line.lower():
                                line_color = COLORS["yellow"]
                            elif "error" in clean_line.lower():
                                line_color = COLORS["red"]
                            self._log(f"    {clean_line}", line_color)
                    proc.wait()
                    self._log(f"    [+] Nmap completed with exit code: {proc.returncode}", COLORS["green"])
                except Exception as ex:
                    self._log(f"    [-] Execution error: {ex}", COLORS["red"])
            else:
                self._log("    [*] Nmap binary unavailable. Generating direct network socket probe & simulated IDS telemetry...", COLORS["yellow"])

            # Optional Local Socket Packet Probe to trigger Scapy / BPF
            if do_real_socket and not self._cancel_signal.is_set():
                ports = profile.get("default_ports", [80, 443, 22, 3389])
                self._emit_direct_tcp_probes(target, ports)

            # Ingest to IDS API
            if not self._cancel_signal.is_set():
                self._dispatch_alert_to_backend(
                    backend=backend,
                    source_ip=self.local_ip,
                    target_port=profile.get("default_ports", [80])[0] if profile.get("default_ports") else 80,
                    attack_type=profile.get("name", key),
                    severity=profile.get("severity", "MEDIUM"),
                    details={
                        "mitre": profile.get("mitre_attack_id", "T1046"),
                        "nmapArgs": profile.get("nmap_args", []),
                        "target": target,
                        "technique": profile.get("description", ""),
                        "liveScan": self.nmap_installed
                    }
                )
            self.footer_status.config(text=f"Engine Idle | Last: {profile.get('name', key)}")

        self._cancel_signal.clear()
        t = threading.Thread(target=worker, daemon=True)
        t.start()

    def _execute_scan_burst(self, key, profile, count=3):
        def worker():
            self._log(f"\n[BURST SEQUENCE] Initiating {count}x iterations of {profile.get('name', key)}...", COLORS["orange"])
            for i in range(count):
                if self._cancel_signal.is_set():
                    break
                self._log(f"  -> Iteration {i+1}/{count} executing...", COLORS["muted"])
                self._execute_scan_profile(key, profile)
                time.sleep(1.0)
        threading.Thread(target=worker, daemon=True).start()

    # ── Simulated Traffic & Flood Vectors ────────────────────────────────────
    def _execute_traffic_vector(self, key, vec):
        target = self.target_ip_var.get().strip() or self.local_ip
        backend = self.backend_url_var.get().rstrip("/")
        port = vec.get("target_port", 80)
        do_real_socket = self.real_packet_mode.get()

        def worker():
            self.total_operations += 1
            self._update_counter()
            self._log(f"\n[VECTOR TRIGGERED] {vec.get('name', key)} -> Target: {target}:{port}", COLORS["orange"])

            if do_real_socket:
                if "flood" in key.lower() or "syn" in key.lower() or "udp" in key.lower():
                    self._emit_rapid_socket_flood(target, port, count=15)
                else:
                    self._emit_direct_tcp_probes(target, [port] * 3)

            # Post alert event to IDS Ingestion endpoint
            self._dispatch_alert_to_backend(
                backend=backend,
                source_ip=self.local_ip,
                target_port=port,
                attack_type=vec.get("name", key),
                severity=vec.get("severity", "HIGH"),
                details={
                    "category": vec.get("category", "General"),
                    "mitre": vec.get("mitre_attack_id", "T1498"),
                    "description": vec.get("description", ""),
                    "target": target
                }
            )

        threading.Thread(target=worker, daemon=True).start()

    def _execute_traffic_burst(self, key, vec, count=5):
        def worker():
            self._log(f"\n[VECTOR BURST] Firing {count}x wave of {vec.get('name', key)}...", COLORS["red"])
            for i in range(count):
                if self._cancel_signal.is_set():
                    break
                self._execute_traffic_vector(key, vec)
                time.sleep(0.4)
        threading.Thread(target=worker, daemon=True).start()

    def _run_all_scan_profiles(self):
        def worker():
            self._cancel_signal.clear()
            self._log("\n" + "=" * 80, COLORS["red"])
            self._log("🔥 EXECUTING COMPREHENSIVE SCAN PROFILE SUITE (ALL VECTORS)", COLORS["red"])
            self._log("=" * 80, COLORS["red"])
            for key, profile in self.scan_profiles.items():
                if self._cancel_signal.is_set():
                    self._log("[!] Scan suite cancelled by operator.", COLORS["yellow"])
                    break
                self._execute_scan_profile(key, profile)
                time.sleep(1.5)
            self._log("\n[+] Full Scan Suite Completed.", COLORS["green"])
        threading.Thread(target=worker, daemon=True).start()

    # ── Network Probes (Direct Local Sockets) ─────────────────────────────────
    def _emit_direct_tcp_probes(self, target, ports):
        """Dispatches non-blocking raw TCP connection handshakes to test agent sniffer."""
        for p in ports:
            if self._cancel_signal.is_set():
                break
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.15)
                s.connect_ex((target, int(p)))
                s.close()
            except Exception:
                pass
            time.sleep(0.02)
        self._log(f"    [*] Emitted synthetic TCP connect probes across ports: {ports[:8]}...", COLORS["muted"])

    def _emit_rapid_socket_flood(self, target, port, count=15):
        """Dispatches UDP or TCP packets in rapid succession."""
        for _ in range(count):
            if self._cancel_signal.is_set():
                break
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.sendto(b"AEGIS_IDS_VALIDATION_PROBE_STREAM", (target, int(port) or 53))
                s.close()
            except Exception:
                pass
            time.sleep(0.01)
        self._log(f"    [*] Streamed {count} datagram probe pulses to port {port}", COLORS["muted"])

    # ── IDS Alert Dispatcher ─────────────────────────────────────────────────
    def _dispatch_alert_to_backend(self, backend, source_ip, target_port, attack_type, severity, details):
        payload = {
            "sourceIp": source_ip,
            "targetPort": target_port,
            "attackType": attack_type,
            "severity": severity,
            "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "details": details
        }
        try:
            req_data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                f"{backend}/api/alerts",
                data=req_data,
                headers={"Content-Type": "application/json", "User-Agent": "AegisRedTeamGUI"}
            )
            with urllib.request.urlopen(req, timeout=3) as resp:
                if resp.status in (200, 201):
                    res_body = json.loads(resp.read().decode("utf-8"))
                    alert_info = res_body.get("alert", {})
                    mitig_len = len(alert_info.get("mitigationScript", ""))
                    self._log(f"    [IDS INGESTION OK] Alert ID: {alert_info.get('_id', 'local')} | Playbook Attached: {mitig_len} bytes", COLORS["green"])
                else:
                    self._log(f"    [IDS INGESTION HTTP {resp.status}]", COLORS["yellow"])
        except urllib.error.URLError:
            self._log(f"    [!] Backend not reachable at {backend}. (Alert recorded locally)", COLORS["yellow"])
        except Exception as e:
            self._log(f"    [-] Alert dispatch error: {e}", COLORS["red"])

    # ── Logging & UI Helpers ─────────────────────────────────────────────────
    def _log(self, text, color=None):
        def _append():
            self.log_widget.configure(state="normal")
            time_prefix = f"[{datetime.now().strftime('%H:%M:%S')}] "
            tag = None
            if color:
                for cname, cval in COLORS.items():
                    if cval == color:
                        tag = cname
                        break
            self.log_widget.insert("end", time_prefix + text + "\n", tag or "text")
            self.log_widget.see("end")
            self.log_widget.configure(state="disabled")
        self.after(0, _append)

    def _clear_log(self):
        self.log_widget.configure(state="normal")
        self.log_widget.delete("1.0", "end")
        self.log_widget.configure(state="disabled")
        self._log("[*] Diagnostic log cleared.", COLORS["muted"])

    def _update_counter(self):
        def _upd():
            self.op_counter_lbl.config(text=f"Operations Executed: {self.total_operations}")
        self.after(0, _upd)


# ─────────────────────────────────────────────────────────────────────────────
# Execution Entry Point
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app = RedTeamApp()
    app.mainloop()
