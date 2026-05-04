import customtkinter as ctk
from tkinter import filedialog
from datetime import datetime

from core.url_scanner import scan_url
from core.log_analyzer import analyze_logs
from core.report_generator import generate_report
from database.db_manager import init_db, save_scan, get_history

# --- Core setup (unchanged logic) ---
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("green")

init_db()

# --- Aggressive neon palette ---
BG = "#000000"            # pure black background for high contrast
CARD = "#071021"          # deep card background
PANEL = "#05060a"         # input panel
NEON_GREEN = "#00FF6A"
NEON_RED = "#FF2E2E"
NEON_YELLOW = "#FFD24A"
NEON_BLUE = "#3AD1FF"
TEXT = "#E6F0FF"
MUTED = "#7A8794"
ACCENT = "#0ff0b3"

# --- Utility: ASCII separators for dramatic effect ---
SEPARATOR = "\n" + "█" * 110 + "\n\n"

# --- UI animation helpers ---
def pulse_widget(widget, colors, idx=0, delay=600):
    try:
        widget.configure(fg_color=colors[idx])
    except Exception:
        pass
    widget.after(delay, lambda: pulse_widget(widget, colors, (idx + 1) % len(colors), delay))

def flash_button_once(btn, flashes=4, on_color=None, off_color=None, delay=120):
    if flashes <= 0:
        return
    current = on_color if flashes % 2 == 0 else off_color
    try:
        btn.configure(fg_color=current)
    except Exception:
        pass
    btn.after(delay, lambda: flash_button_once(btn, flashes - 1, on_color, off_color, delay))

# --- Core functions (logic preserved, messages and formatting updated) ---
def clear_result():
    result_box.configure(state="normal")
    result_box.delete("1.0", "end")

def run_scan():
    url = url_entry.get().strip()

    if not url:
        clear_result()
        result_box.insert("end", "🚨 INPUT REQUIRED: Enter target URL!\n", "yellow")
        return

    # Visual feedback: flash scan button
    flash_button_once(scan_button, flashes=6, on_color="#00ff8f", off_color=NEON_GREEN)

    result = scan_url(url)
    save_scan("URL Scan", result["url"], result["verdict"], result["risk_score"])

    clear_result()

    verdict = result["verdict"]

    if verdict == "Malicious":
        color_tag = "red"
        badge = "🚨 THREAT LEVEL: MALICIOUS"
    elif verdict == "Suspicious":
        color_tag = "yellow"
        badge = "⚠ THREAT LEVEL: SUSPICIOUS"
    else:
        color_tag = "green"
        badge = "🟢 THREAT LEVEL: LOW / SAFE"

    result_box.insert("end", "🛡 CYBERSHIELD AI // THREAT DEFENSE REPORT\n", "blue")
    result_box.insert("end", SEPARATOR)

    result_box.insert("end", f"{badge}\n\n", color_tag)
    result_box.insert("end", f"🔗 TARGET: {result['url']}\n")
    result_box.insert("end", f"🧠 VERDICT: {verdict}\n", color_tag)
    result_box.insert("end", f"📊 RISK SCORE: {result['risk_score']}/100\n")
    result_box.insert("end", f"🤖 ML CONFIDENCE: {result['ml_confidence']}%\n\n")

    result_box.insert("end", "🔎 ANALYSIS SUMMARY:\n", "blue")
    for reason in result["explanation"]["reasons"]:
        result_box.insert("end", f" • {reason}\n")

    result_box.insert("end", "\n💥 POTENTIAL IMPACT:\n", "yellow")
    for impact in result["explanation"]["possible_impacts"]:
        result_box.insert("end", f" • {impact}\n")

    result_box.insert("end", "\n🛡 ACTION PLAN (IMMEDIATE):\n", "green")
    for rec in result["explanation"]["recommendations"]:
        result_box.insert("end", f" • {rec}\n")

    result_box.insert("end", SEPARATOR)
    result_box.insert("end", "🛡 OPERATION COMPLETE: Threat defense executed.\n", "green")

def run_log_analysis():
    file_path = filedialog.askopenfilename(
        title="Select CSV Log File",
        filetypes=[("CSV Files", "*.csv")]
    )

    if not file_path:
        return

    result = analyze_logs(file_path)

    clear_result()

    if "error" in result:
        result_box.insert("end", f"❌ ANALYSIS ERROR:\n{result['error']}\n", "red")
        return

    save_scan("CSV Log Analysis", file_path, result["risk_level"], result["risk_score"])

    risk_level = result["risk_level"]

    if risk_level == "High":
        color_tag = "red"
        badge = "🚨 LOG THREAT: HIGH"
    elif risk_level == "Medium":
        color_tag = "yellow"
        badge = "⚠ LOG THREAT: MEDIUM"
    else:
        color_tag = "green"
        badge = "🟢 LOG THREAT: LOW"

    result_box.insert("end", "📁 CYBERSHIELD // CSV LOG ANALYSIS\n", "blue")
    result_box.insert("end", SEPARATOR)

    result_box.insert("end", f"{badge}\n\n", color_tag)
    result_box.insert("end", f"📄 FILE: {file_path}\n")
    result_box.insert("end", f"📊 ROWS ANALYZED: {result['total_rows']}\n")
    result_box.insert("end", f"🧠 RISK LEVEL: {risk_level}\n", color_tag)
    result_box.insert("end", f"🔥 RISK SCORE: {result['risk_score']}/100\n\n")

    result_box.insert("end", "🌐 SUSPICIOUS IPS:\n", "blue")
    if result["suspicious_ips"]:
        for item in result["suspicious_ips"]:
            result_box.insert("end", f" • {item['ip']} | Count: {item['count']} | {item['reason']}\n")
    else:
        result_box.insert("end", " • None detected\n", "green")

    result_box.insert("end", "\n🔐 BRUTE-FORCE INDICATORS:\n", "yellow")
    if result["brute_force_ips"]:
        for item in result["brute_force_ips"]:
            result_box.insert("end", f" • {item['ip']} | Failed Attempts: {item['failed_attempts']} | {item['reason']}\n")
    else:
        result_box.insert("end", " • None detected\n", "green")

    result_box.insert("end", "\n🔗 MALICIOUS URLS FOUND:\n", "yellow")
    if result["malicious_urls"]:
        for url in result["malicious_urls"]:
            result_box.insert("end", f" • {url}\n")
    else:
        result_box.insert("end", " • None detected\n", "green")

    result_box.insert("end", "\n🚨 THREAT EVENTS:\n", "red")
    if result["threat_events"]:
        for event in result["threat_events"]:
            result_box.insert("end", f" • {event}\n")
    else:
        result_box.insert("end", " • None detected\n", "green")

    result_box.insert("end", "\n🛡 ACTION PLAN (LOGS):\n", "green")
    for rec in result["recommendations"]:
        result_box.insert("end", f" • {rec}\n")

    result_box.insert("end", SEPARATOR)
    result_box.insert("end", "🛡 LOG ANALYSIS COMPLETE: SOC notified if required.\n", "green")

def show_history():
    rows = get_history()

    clear_result()
    result_box.insert("end", "🕒 CYBERSHIELD // SCAN HISTORY\n", "blue")
    result_box.insert("end", SEPARATOR)

    if not rows:
        result_box.insert("end", "⚠ NO HISTORY FOUND\n", "yellow")
        return

    for row in rows:
        scan_type, target, verdict, risk_score, timestamp = row

        if str(verdict).lower() in ["malicious", "high"]:
            color_tag = "red"
        elif str(verdict).lower() in ["suspicious", "medium"]:
            color_tag = "yellow"
        else:
            color_tag = "green"

        result_box.insert("end", f"⏱ TIME: {timestamp}\n")
        result_box.insert("end", f"🧪 TYPE: {scan_type}\n")
        result_box.insert("end", f"🎯 TARGET: {target}\n")
        result_box.insert("end", f"🧠 VERDICT: {verdict}\n", color_tag)
        result_box.insert("end", f"📊 RISK SCORE: {risk_score}\n")
        result_box.insert("end", "-" * 110 + "\n")

def export_report():
    content = result_box.get("1.0", "end").strip()

    if not content:
        result_box.insert("end", "\n\n⚠ EXPORT FAILED: No report content.\n", "yellow")
        return

    try:
        filename = f"CyberShield_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        path = generate_report(filename, content)

        result_box.insert("end", "\n\n✅ REPORT EXPORTED: Evidence saved.\n", "green")
        result_box.insert("end", f"📄 PATH: {path}\n", "blue")

    except Exception as e:
        result_box.insert("end", f"\n\n❌ EXPORT ERROR: {e}\n", "red")

# --- App UI (visuals upgraded, layout preserved) ---
app = ctk.CTk()
app.title("CyberShield AI - Threat Defense Console")
app.geometry("1650x1000")
app.minsize(1300, 850)
app.configure(fg_color=BG)

try:
    app.state("zoomed")
except Exception:
    pass

main_frame = ctk.CTkFrame(app, fg_color=BG)
main_frame.pack(fill="both", expand=True)

# Header with aggressive styling
header_frame = ctk.CTkFrame(main_frame, fg_color=BG)
header_frame.pack(pady=(10, 6))

title = ctk.CTkLabel(
    header_frame,
    text="🛡 CYBERSHIELD AI",
    font=("Orbitron", 52, "bold"),
    text_color=NEON_GREEN
)
title.pack()

# Red neon underline
underline = ctk.CTkFrame(header_frame, fg_color=NEON_RED, height=4, corner_radius=2)
underline.pack(fill="x", padx=220, pady=(6, 0))

subtitle = ctk.CTkLabel(
    header_frame,
    text="THREAT DEFENSE CONSOLE  •  URL SCANNER  •  CSV LOG ANALYZER  •  INCIDENT REPORTER",
    font=("Consolas", 14, "italic"),
    text_color=NEON_BLUE
)
subtitle.pack(pady=6)

version = ctk.CTkLabel(
    header_frame,
    text="Version 1.0  •  Built by Dinesh Kumar  •  Mini SOC Desktop Tool",
    font=("Consolas", 11),
    text_color=MUTED
)
version.pack(pady=2)

# Status stickers (more contrast)
stats_frame = ctk.CTkFrame(main_frame, fg_color=BG)
stats_frame.pack(padx=25, pady=(8, 6), fill="x")

stickers = [
    ("⚡", "PROTECTION ACTIVE", NEON_GREEN),
    ("🧠", "AI MODEL LOADED", NEON_BLUE),
    ("📁", "LOG ANALYZER READY", NEON_YELLOW),
    ("📄", "REPORT ENGINE READY", NEON_RED),
]

for icon, text, color in stickers:
    card = ctk.CTkFrame(stats_frame, fg_color=CARD, corner_radius=14, border_width=1, border_color=color)
    card.pack(side="left", expand=True, fill="x", padx=8)
    label = ctk.CTkLabel(
        card,
        text=f"{icon} {text}",
        font=("Consolas", 14, "bold"),
        text_color=color
    )
    label.pack(pady=12)

# Input card
input_card = ctk.CTkFrame(main_frame, fg_color=CARD, corner_radius=18, border_width=1, border_color="#0b1220")
input_card.pack(padx=25, pady=(10, 8), fill="x")

url_entry = ctk.CTkEntry(
    input_card,
    width=1000,
    height=52,
    placeholder_text="ENTER TARGET URL FOR THREAT SCAN...",
    font=("Consolas", 16, "bold"),
    fg_color=PANEL,
    border_color=NEON_GREEN,
    border_width=2,
    text_color=TEXT
)
url_entry.pack(pady=(18, 12))

button_frame = ctk.CTkFrame(input_card, fg_color="transparent")
button_frame.pack(pady=(6, 18))

scan_button = ctk.CTkButton(
    button_frame,
    text="🔍 LAUNCH SCAN",
    width=260,
    height=52,
    fg_color=NEON_GREEN,
    hover_color="#00e07a",
    text_color="#000000",
    font=("Orbitron", 15, "bold"),
    command=run_scan
)
scan_button.pack(side="left", padx=12)

log_button = ctk.CTkButton(
    button_frame,
    text="📁 ANALYZE CSV LOGS",
    width=260,
    height=52,
    fg_color=NEON_BLUE,
    hover_color="#2ec8ff",
    text_color="#000000",
    font=("Orbitron", 15, "bold"),
    command=run_log_analysis
)
log_button.pack(side="left", padx=12)

history_button = ctk.CTkButton(
    button_frame,
    text="🕒 VIEW HISTORY",
    width=220,
    height=52,
    fg_color=NEON_YELLOW,
    hover_color="#ffd86b",
    text_color="#000000",
    font=("Orbitron", 15, "bold"),
    command=show_history
)
history_button.pack(side="left", padx=12)

export_button = ctk.CTkButton(
    button_frame,
    text="📄 EXPORT REPORT",
    width=220,
    height=52,
    fg_color=NEON_RED,
    hover_color="#ff5a5a",
    text_color="#000000",
    font=("Orbitron", 15, "bold"),
    command=export_report
)
export_button.pack(side="left", padx=12)

# Console frame with neon border and pulsing LIVE badge
console_frame = ctk.CTkFrame(main_frame, fg_color=CARD, corner_radius=20, border_width=2, border_color=NEON_GREEN)
console_frame.pack(padx=25, pady=(8, 12), fill="both", expand=True)

console_header = ctk.CTkFrame(console_frame, fg_color="transparent")
console_header.pack(fill="x", padx=24, pady=(12, 6))

console_title = ctk.CTkLabel(
    console_header,
    text="🧪 SECURITY ANALYSIS CONSOLE",
    font=("Orbitron", 24, "bold"),
    text_color=NEON_GREEN
)
console_title.pack(side="left")

console_badge = ctk.CTkLabel(
    console_header,
    text="LIVE DEFENSE",
    font=("Consolas", 12, "bold"),
    text_color="#000000",
    fg_color=NEON_GREEN,
    corner_radius=8,
    padx=14,
    pady=6
)
console_badge.pack(side="right")

# Start pulsing the LIVE badge between neon green and neon red to draw attention
pulse_widget(console_badge, [NEON_GREEN, NEON_RED], idx=0, delay=700)

result_box = ctk.CTkTextbox(
    console_frame,
    font=("Consolas", 18),
    fg_color="#000000",
    text_color=TEXT,
    border_color=NEON_GREEN,
    border_width=2,
    corner_radius=14,
    wrap="word"
)
result_box.pack(padx=24, pady=(8, 24), fill="both", expand=True)

# Tag colors
result_box.tag_config("red", foreground=NEON_RED)
result_box.tag_config("yellow", foreground=NEON_YELLOW)
result_box.tag_config("green", foreground=NEON_GREEN)
result_box.tag_config("blue", foreground=NEON_BLUE)

# Initial aggressive welcome text
result_box.insert("end", "🛡 CYBERSHIELD AI // THREAT DEFENSE CONSOLE\n\n", "green")
result_box.insert("end", "🚀 READY: Choose an action to engage the defense matrix\n\n", "blue")
result_box.insert("end", " • LAUNCH SCAN: Scan a suspicious website URL\n")
result_box.insert("end", " • ANALYZE LOGS: Investigate CSV security logs\n")
result_box.insert("end", " • VIEW HISTORY: Review previous scans\n")
result_box.insert("end", " • EXPORT: Generate incident evidence report\n\n")
result_box.insert("end", "⚡ SYSTEM STATUS: PROTECTION ENGINE ACTIVE\n", "green")
result_box.insert("end", "🧠 AI ENGINE: MODEL LOADED\n", "blue")
result_box.insert("end", "📁 LOG ANALYZER: STANDBY\n", "yellow")
result_box.insert("end", "📄 REPORT ENGINE: READY\n", "red")

footer = ctk.CTkLabel(
    main_frame,
    text="CyberShield AI detects suspicious URLs, brute-force patterns, malicious log activity, and generates security reports.",
    font=("Consolas", 12),
    text_color=MUTED
)
footer.pack(pady=(0, 8))

app.mainloop()
