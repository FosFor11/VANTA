import tkinter as tk
from datetime import datetime
import random
import threading
import time

# ====================== CORE ======================
from core.engine import VantaEngine
from core.target import Target
from core.findings import FindingsManager
from core.scanner import Scanner
from reports.txt import save_txt
from reports.json import save_json


class VantaApp:

    # =========================================================
    # COLORS
    # =========================================================

    BG = "#020403"
    PANEL = "#050806"

    GREEN = "#20ff9a"
    GREEN_BRIGHT = "#63ffc0"
    GREEN_DIM = "#0b6b43"

    TEXT = "#d8ffe9"
    MUTED = "#557766"

    RED = "#ff3030"
    ORANGE = "#ff8a20"
    YELLOW = "#ffd21f"
    BLUE = "#36a8ff"
    GRAY = "#8b9991"

    def __init__(self, root):
        self.root = root

        self.root.title("VANTA // WEB SECURITY AUDITOR")
        self.root.geometry("1400x850")
        self.root.minsize(1100, 700)
        self.root.configure(bg=self.BG)

        # =====================================================
        # STATE
        # =====================================================
        self.scanning = False
        self.activity_value = 0
        self.activity_direction = 1
        self.activity_pulse = 0
        self.matrix_columns = []

        # =====================================================
        # ENGINE
        # =====================================================
        self.engine = VantaEngine()
        self.findings_manager = FindingsManager()

        self.engine.on_log = self.log
        self.engine.on_status = self.set_status

        self.build_interface()

        # =====================================================
        # INITIAL LOG
        # =====================================================
        self.log("VANTA initialization started")
        self.log("Security engine ........ READY")
        self.log("Network engine ........ READY")
        self.log("Analysis engine ....... READY")
        self.log("Report engine ......... READY")
        self.log("System status ........ READY")
        self.log("Safe mode ............. ON")

        # =====================================================
        # START BACKGROUND ANIMATIONS
        # =====================================================
        self.update_clock()
        self.matrix_animation()
        self.idle_activity()

    # =========================================================
    # BUILD INTERFACE
    # =========================================================

    def build_interface(self):

        # =====================================================
        # HEADER
        # =====================================================
        header = tk.Frame(self.root, bg=self.BG, height=155)
        header.pack(fill="x", padx=25, pady=(12, 0))
        header.pack_propagate(False)

        self.matrix_canvas = tk.Canvas(header, bg=self.BG, highlightthickness=0)
        self.matrix_canvas.place(x=0, y=0, relwidth=1, relheight=1)

        logo_shadow = tk.Label(
            header, text="VANTA", bg=self.BG, fg="#073a25",
            font=("Segoe UI", 46, "bold")
        )
        logo_shadow.place(relx=0.5, rely=0.30, anchor="center")

        logo = tk.Label(
            header, text="VANTA", bg=self.BG, fg="#ecfff5",
            font=("Segoe UI", 42, "bold")
        )
        logo.place(relx=0.5, rely=0.285, anchor="center")

        tk.Label(
            header, text="WEB SECURITY  //  AUDITOR",
            bg=self.BG, fg=self.GREEN,
            font=("Consolas", 10, "bold")
        ).place(relx=0.5, rely=0.60, anchor="center")

        self.status_label = tk.Label(
            header, text="● READY", bg=self.BG, fg=self.GREEN,
            font=("Consolas", 9, "bold")
        )
        self.status_label.place(relx=0.5, rely=0.76, anchor="center")

        tk.Frame(header, bg=self.GREEN, height=1).place(
            relx=0.15, rely=0.94, relwidth=0.70
        )

        # =====================================================
        # TARGET
        # =====================================================
        target_section = tk.Frame(self.root, bg=self.BG)
        target_section.pack(fill="x", padx=25, pady=(8, 8))

        tk.Label(
            target_section, text="TARGET", bg=self.BG, fg=self.GREEN,
            font=("Consolas", 10, "bold")
        ).pack(anchor="w")

        target_row = tk.Frame(target_section, bg=self.BG)
        target_row.pack(fill="x", pady=(5, 0))

        target_border = tk.Frame(target_row, bg=self.GREEN, padx=1, pady=1)
        target_border.pack(side="left", fill="x", expand=True)

        self.target_entry = tk.Entry(
            target_border, bg="#030604", fg=self.TEXT,
            insertbackground=self.GREEN,
            selectbackground="#164f39",
            selectforeground="#ffffff",
            relief="flat", bd=0,
            font=("Consolas", 12)
        )
        self.target_entry.pack(fill="x", ipady=9, padx=3)

        self.start_button = self.make_button(target_row, "START", self.start_scan)
        self.start_button.pack(side="left", padx=(8, 0))

        self.stop_button = self.make_button(target_row, "STOP", self.stop_scan)
        self.stop_button.pack(side="left", padx=(6, 0))

        self.clear_button = self.make_button(target_row, "CLEAR", self.clear_console)
        self.clear_button.pack(side="left", padx=(6, 0))

        self.save_button = self.make_button(target_row, "SAVE", self.save_log)
        self.save_button.pack(side="left", padx=(6, 0))

        # =====================================================
        # ACTIVITY
        # =====================================================
        activity_frame = tk.Frame(self.root, bg=self.BG)
        activity_frame.pack(fill="x", padx=25, pady=(2, 10))

        activity_header = tk.Frame(activity_frame, bg=self.BG)
        activity_header.pack(fill="x")

        tk.Label(
            activity_header, text="SYSTEM ACTIVITY", bg=self.BG, fg=self.MUTED,
            font=("Consolas", 8, "bold")
        ).pack(side="left")

        self.activity_percent = tk.Label(
            activity_header, text="READY", bg=self.BG, fg=self.GREEN,
            font=("Consolas", 8, "bold")
        )
        self.activity_percent.pack(side="right")

        self.activity_canvas = tk.Canvas(
            activity_frame, height=18, bg="#010201",
            highlightthickness=1, highlightbackground="#155c3c"
        )
        self.activity_canvas.pack(fill="x", pady=(4, 0))

        # =====================================================
        # MAIN CONTENT
        # =====================================================
        content = tk.Frame(self.root, bg=self.BG)
        content.pack(fill="both", expand=True, padx=25, pady=(0, 10))

        # =====================================================
        # CONSOLE
        # =====================================================
        console_frame = tk.Frame(content, bg=self.BG)
        console_frame.pack(side="left", fill="both", expand=True, padx=(0, 8))

        tk.Label(
            console_frame, text="CONSOLE", bg=self.BG, fg=self.GREEN,
            font=("Consolas", 10, "bold")
        ).pack(anchor="w", pady=(0, 5))

        console_border = tk.Frame(console_frame, bg=self.GREEN, padx=1, pady=1)
        console_border.pack(fill="both", expand=True)

        self.console = tk.Text(
            console_border, bg="#030604", fg=self.TEXT,
            insertbackground=self.GREEN,
            selectbackground="#164f39",
            selectforeground="#ffffff",
            relief="flat", bd=0, wrap="word",
            font=("Consolas", 10), padx=12, pady=12
        )
        self.console.pack(side="left", fill="both", expand=True)

        scrollbar = tk.Scrollbar(
            console_border, command=self.console.yview,
            bg="#071009", troughcolor="#020302",
            activebackground=self.GREEN, relief="flat"
        )
        scrollbar.pack(side="right", fill="y")
        self.console.configure(yscrollcommand=scrollbar.set)
        self.console.bind("<Control-c>", self.copy_console)

        # =====================================================
        # FINDINGS
        # =====================================================
        findings_frame = tk.Frame(content, bg=self.BG, width=300)
        findings_frame.pack(side="right", fill="y")
        findings_frame.pack_propagate(False)

        tk.Label(
            findings_frame, text="SECURITY FINDINGS", bg=self.BG, fg=self.GREEN,
            font=("Consolas", 10, "bold")
        ).pack(anchor="w", pady=(0, 5))

        findings_border = tk.Frame(findings_frame, bg=self.GREEN, padx=1, pady=1)
        findings_border.pack(fill="both", expand=True)

        self.findings_box = tk.Frame(findings_border, bg="#030604")
        self.findings_box.pack(fill="both", expand=True)

        self.finding_labels = {}

        self.create_finding("CRITICAL", "0", self.RED)
        self.create_finding("HIGH", "0", self.ORANGE)
        self.create_finding("MEDIUM", "0", self.YELLOW)
        self.create_finding("LOW", "0", self.BLUE)
        self.create_finding("INFO", "0", self.GRAY)

        # =====================================================
        # FOOTER
        # =====================================================
        footer = tk.Frame(self.root, bg=self.BG, height=28)
        footer.pack(fill="x", padx=25, pady=(0, 8))
        footer.pack_propagate(False)

        self.footer_label = tk.Label(
            footer, text="VANTA // SYSTEM READY", bg=self.BG, fg=self.MUTED,
            font=("Consolas", 8)
        )
        self.footer_label.pack(side="left")

        self.time_label = tk.Label(
            footer, text="", bg=self.BG, fg=self.MUTED,
            font=("Consolas", 8)
        )
        self.time_label.pack(side="right")

    # =========================================================
    # BUTTON
    # =========================================================

    def make_button(self, parent, text, command):
        outer = tk.Frame(parent, bg=self.GREEN, padx=1, pady=1)

        button = tk.Button(
            outer, text=text, command=command,
            bg=self.BG, fg=self.GREEN,
            activebackground=self.GREEN,
            activeforeground="#020302",
            relief="flat", bd=0, padx=18, pady=8,
            font=("Consolas", 9, "bold"),
            cursor="hand2"
        )
        button.pack()

        def on_enter(event):
            button.configure(bg="#0b2419", fg=self.GREEN_BRIGHT)

        def on_leave(event):
            button.configure(bg=self.BG, fg=self.GREEN)

        button.bind("<Enter>", on_enter)
        button.bind("<Leave>", on_leave)

        return outer

    # =========================================================
    # FINDING
    # =========================================================

    def create_finding(self, name, value, color):
        row = tk.Frame(self.findings_box, bg="#030604", height=58)
        row.pack(fill="x", padx=10, pady=6)
        row.pack_propagate(False)

        tk.Frame(row, bg=color, width=4).pack(side="left", fill="y")

        tk.Label(
            row, text=name, bg="#030604", fg="#d7e9df",
            font=("Consolas", 10, "bold")
        ).pack(side="left", padx=12)

        label = tk.Label(
            row, text=value, bg="#030604", fg=color,
            font=("Consolas", 15, "bold")
        )
        label.pack(side="right", padx=12)

        self.finding_labels[name] = label

    def update_findings_display(self, counts: dict):
        for severity, count in counts.items():
            if severity in self.finding_labels:
                self.finding_labels[severity].config(text=str(count))

    # =========================================================
    # LOG
    # =========================================================

    def log(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.console.insert("end", f"[{timestamp}] {message}\n")
        self.console.see("end")

    # =========================================================
    # START SCAN
    # =========================================================

    def start_scan(self):
        target_text = self.target_entry.get().strip()

        if not target_text:
            self.log("ERROR: target is empty")
            self.set_status("● ERROR", self.RED)
            return

        if self.scanning:
            self.log("WARNING: scan already running")
            return

        target = Target(target_text)
        if not target.is_valid:
            self.log(f"ERROR: invalid target — {target.error}")
            self.set_status("● ERROR", self.RED)
            return

        self.scanning = True
        self.activity_value = 0
        self.findings_manager.clear()
        self.update_findings_display(self.findings_manager.get_counts())

        self.set_status("● SCANNING", self.GREEN)
        self.footer_label.config(text=f"VANTA // SCANNING // {target}")
        self.activity_percent.config(text="ACTIVE")

        self.log(f"Target accepted: {target}")
        self.log("Scan engine initialized")
        self.log("Safe mode: ON")
        self.log("Starting modules...")

        def run():
            scanner = Scanner(
                target=target,
                findings=self.findings_manager,
                log_callback=lambda msg: self.root.after(0, lambda: self.log(msg))
            )
            scanner.run()

            counts = self.findings_manager.get_counts()
            self.root.after(0, lambda: self.update_findings_display(counts))
            self.root.after(0, lambda: self.set_status("● COMPLETED", self.GREEN))
            self.root.after(0, lambda: self.footer_label.config(text="VANTA // SCAN COMPLETED"))
            self.root.after(0, lambda: self.activity_percent.config(text="STANDBY"))
            self.scanning = False

        threading.Thread(target=run, daemon=True).start()

    # =========================================================
    # STOP
    # =========================================================

    def stop_scan(self):
        if not self.scanning:
            self.log("INFO: no active scan")
            return

        self.scanning = False
        self.activity_percent.config(text="STANDBY")
        self.set_status("● STOPPED", self.ORANGE)
        self.footer_label.config(text="VANTA // SCAN STOPPED")
        self.log("Scan stopped by user")

    # =========================================================
    # CLEAR
    # =========================================================

    def clear_console(self):
        self.console.delete("1.0", "end")
        self.findings_manager.clear()
        self.update_findings_display(self.findings_manager.get_counts())
        self.log("Console and findings cleared")

    # =========================================================
    # SAVE
    # =========================================================

    def save_log(self):
        target_text = self.target_entry.get().strip() or "unknown"
        try:
            target = Target(target_text)
            save_txt(target, self.findings_manager, self.log)
            save_json(target, self.findings_manager, self.log)
            self.log("Reports saved to Desktop (TXT + JSON)")
        except Exception as e:
            self.log(f"ERROR saving reports: {e}")

    # =========================================================
    # COPY
    # =========================================================

    def copy_console(self, event=None):
        try:
            selected = self.console.get("sel.first", "sel.last")
            self.root.clipboard_clear()
            self.root.clipboard_append(selected)
        except tk.TclError:
            pass
        return "break"

    # =========================================================
    # STATUS
    # =========================================================

    def set_status(self, text, color):
        self.status_label.configure(text=text, fg=color)

    # =========================================================
    # ACTIVITY
    # =========================================================

    def idle_activity(self):
        if self.scanning:
            self.activity_value += 2
            if self.activity_value >= 100:
                self.activity_value = 0
            self.activity_percent.config(text=f"ACTIVE {self.activity_value:02d}%")
        else:
            self.activity_value += 1
            if self.activity_value >= 100:
                self.activity_value = 0
            self.activity_percent.config(text="STANDBY")

        self.draw_activity()
        self.root.after(35, self.idle_activity)

    def draw_activity(self):
        self.activity_canvas.delete("all")
        width = self.activity_canvas.winfo_width()
        height = self.activity_canvas.winfo_height()

        if width <= 5:
            return

        segment_count = 100
        segment_width = width / segment_count

        for i in range(segment_count):
            x1 = i * segment_width
            x2 = x1 + segment_width - 1
            self.activity_canvas.create_rectangle(
                x1, 4, x2, height - 5, fill="#06140d", outline=""
            )

        for i in range(int(self.activity_value)):
            x1 = i * segment_width
            x2 = x1 + segment_width - 1

            if i > self.activity_value - 8:
                color = self.GREEN_BRIGHT
            elif i > self.activity_value - 25:
                color = self.GREEN
            else:
                color = self.GREEN_DIM

            self.activity_canvas.create_rectangle(
                x1, 4, x2, height - 5, fill=color, outline=""
            )

        beam_x = self.activity_value / 100 * width
        self.activity_canvas.create_rectangle(
            beam_x - 3, 1, beam_x + 3, height - 2,
            fill=self.GREEN_BRIGHT, outline=""
        )
        self.activity_canvas.create_oval(
            beam_x - 2, 4, beam_x + 2, height - 5,
            fill="#ffffff", outline=""
        )

    # =========================================================
    # MATRIX ANIMATION
    # =========================================================

    def matrix_animation(self):
        self.matrix_canvas.delete("all")
        width = self.matrix_canvas.winfo_width()
        height = self.matrix_canvas.winfo_height()

        if width > 10:
            column_count = int(width / 17)

            if len(self.matrix_columns) != column_count:
                self.matrix_columns = [
                    random.randint(-12, 0) for _ in range(column_count)
                ]

            chars = "01ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789アイウエオカキクケコ"

            for index in range(column_count):
                x = index * 17
                position = self.matrix_columns[index]

                for trail in range(5):
                    y = (position - trail) * 13
                    if y < 0 or y > height:
                        continue

                    char = random.choice(chars)

                    if trail == 0:
                        color = "#27d98b"
                    elif trail == 1:
                        color = "#168957"
                    elif trail == 2:
                        color = "#0d653f"
                    elif trail == 3:
                        color = "#09452c"
                    else:
                        color = "#06331f"

                    self.matrix_canvas.create_text(
                        x, y, text=char, fill=color,
                        font=("Consolas", 9), anchor="nw"
                    )

                self.matrix_columns[index] += 1
                if position * 13 > height + 60:
                    self.matrix_columns[index] = random.randint(-15, -2)

        self.root.after(75, self.matrix_animation)

    # =========================================================
    # CLOCK
    # =========================================================

    def update_clock(self):
        now = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
        self.time_label.configure(text=now)
        self.root.after(1000, self.update_clock)


# =============================================================
# MAIN
# =============================================================

def main():
    root = tk.Tk()
    app = VantaApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()