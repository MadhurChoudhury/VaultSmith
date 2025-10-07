import tkinter as tk
from tkinter import messagebox
from pathlib import Path
import json
import datetime
from vaultsmith.crypto import create_vault_envelope, open_vault_envelope

# Path to your existing vault
VAULT_FILE = Path("vault.json")
CONFIG_FILE = Path("config.json")
# ---------- Themes ----------
THEMES = {
    "dark": {
        "BG": "#0F172A",
        "FG": "#E2E8F0",
        "ACCENT": "#38BDF8",
        "ENTRY_BG": "#1E293B",
        "SUCCESS": "#4ADE80",
        "ERROR": "#F87171"
    },
    "light": {
        "BG": "#FFF4DB",
        "FG": "#1F2933",
        "ACCENT": "#FF6B6B",
        "ENTRY_BG": "#FFFFFF",
        "SUCCESS": "#2ECC71",
        "ERROR": "#E8505B"
    }
}


class VaultApp:
    def __init__(self, root):
        self.root = root
        self.root.title("VaultSmith")
        self.root.geometry("420x300")

        # Initialize theme
        # Load theme from config (or default to dark)
        if CONFIG_FILE.exists():
            try:
                cfg = json.loads(CONFIG_FILE.read_text())
                self.theme_mode = cfg.get("theme", "dark")
            except Exception:
                self.theme_mode = "dark"
        else:
            self.theme_mode = "dark"

        self.theme = THEMES[self.theme_mode]
        self.root.config(bg=self.theme["BG"])
        
        self.root.config(bg=self.theme["BG"])

        self.vault_data = None
        self.build_unlock_screen()

    # ------------------------------
    def clear_screen(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    # ------------------------------
    def build_unlock_screen(self):
        self.clear_screen()

        self.root.config(bg=self.theme["BG"])
        tk.Label(self.root, text="🔐 VaultSmith", font=("Segoe UI", 18, "bold"),
                 bg=self.theme["BG"], fg=self.theme["FG"]).pack(pady=20)

        tk.Label(self.root, text="Enter Master Password:",
                 bg=self.theme["BG"], fg=self.theme["FG"], font=("Segoe UI", 11)).pack()

        self.password_entry = tk.Entry(self.root, show="*", bg=self.theme["ENTRY_BG"],
                                       fg=self.theme["FG"], relief="flat",
                                       insertbackground=self.theme["FG"], width=30)
        self.password_entry.pack(pady=8)
        self.password_entry.focus()
        self.password_entry.bind("<Return>", lambda event: self.unlock_vault())

        unlock_btn = tk.Button(self.root, text="Unlock Vault", bg=self.theme["ACCENT"], fg="white",
                               activebackground="#005A9E", relief="flat", command=self.unlock_vault)
        unlock_btn.pack(pady=10)

        create_btn = tk.Label(self.root, text="New here? Create Vault", bg=self.theme["BG"],
                              fg=self.theme["ACCENT"], font=("Segoe UI", 9, "underline"),
                              cursor="hand2")
        create_btn.pack(pady=(4, 10))
        create_btn.bind("<Button-1>", lambda e: self.handle_create_vault_click())

        self.status_label = tk.Label(self.root, text="", bg=self.theme["BG"], fg=self.theme["FG"])
        self.status_label.pack(pady=5)

        # Theme toggle
        tk.Button(self.root, text=f"Switch to {'Light' if self.theme_mode == 'dark' else 'Dark'} Mode",
                  bg=self.theme["ENTRY_BG"], fg=self.theme["ACCENT"], relief="flat",
                  command=self.toggle_theme).pack(pady=(4, 10))

    # ------------------------------
    def unlock_vault(self):
        password = self.password_entry.get()
        self.master_password = password

        if not VAULT_FILE.exists():
            self.prompt_create_vault()
            return

        try:
            envelope = VAULT_FILE.read_text()
            plaintext = open_vault_envelope(password, envelope)
            self.vault_data = json.loads(plaintext)
            self.show_vault_screen()
        except Exception:
            self.status_label.config(text="❌ Wrong password or corrupted vault.",
                                     fg=self.theme["ERROR"])

    # ------------------------------
    def handle_create_vault_click(self):
        if VAULT_FILE.exists():
            messagebox.showinfo("Vault Exists", "You already have a vault set up.")
            return
        self.prompt_create_vault()

    # ------------------------------
    def prompt_create_vault(self):
        self.clear_screen()
        win = tk.Toplevel(self.root)
        win.title("Create New Vault")
        win.config(bg=self.theme["BG"])
        win.geometry("360x220")

        tk.Label(win, text="🛠️ No vault found — let’s create a new one!",
                 bg=self.theme["BG"], fg=self.theme["ACCENT"],
                 font=("Segoe UI", 10, "italic")).pack(pady=(10, 4))

        tk.Label(win, text="Set a Master Password", bg=self.theme["BG"], fg=self.theme["FG"],
                 font=("Segoe UI", 12, "bold")).pack(pady=10)

        tk.Label(win, text="Password:", bg=self.theme["BG"], fg=self.theme["FG"]).pack()
        pw1 = tk.Entry(win, show="*", bg=self.theme["ENTRY_BG"], fg=self.theme["FG"],
                       relief="flat", insertbackground=self.theme["FG"], width=30)
        pw1.pack(pady=4)

        tk.Label(win, text="Confirm Password:", bg=self.theme["BG"], fg=self.theme["FG"]).pack()
        pw2 = tk.Entry(win, show="*", bg=self.theme["ENTRY_BG"], fg=self.theme["FG"],
                       relief="flat", insertbackground=self.theme["FG"], width=30)
        pw2.pack(pady=4)

        def create_action():
            p1, p2 = pw1.get(), pw2.get()
            if p1 != p2 or not p1:
                messagebox.showerror("Error", "Passwords do not match or are empty.")
                return

            vault_data = {
                "created": datetime.datetime.now().isoformat(timespec="seconds"),
                "entries": []
            }
            envelope = create_vault_envelope(p1, json.dumps(vault_data).encode("utf-8"))
            VAULT_FILE.write_text(envelope)
            messagebox.showinfo("Vault Created", "New vault created successfully!")

            self.vault_data = vault_data
            win.destroy()
            self.show_vault_screen()

        tk.Button(win, text="Create Vault", bg=self.theme["ACCENT"], fg="white",
                  relief="flat", command=create_action).pack(pady=10)

    # ------------------------------
    def show_vault_screen(self):
        self.clear_screen()
        self.root.config(bg=self.theme["BG"])

        tk.Label(self.root, text="✅ Vault Unlocked", bg=self.theme["BG"], fg=self.theme["SUCCESS"],
                 font=("Segoe UI", 14, "bold")).pack(pady=10)

        tk.Label(self.root, text="Search:", bg=self.theme["BG"], fg=self.theme["FG"],
                 font=("Segoe UI", 10)).pack()
        search_var = tk.StringVar()
        search_entry = tk.Entry(self.root, textvariable=search_var, bg=self.theme["ENTRY_BG"],
                                fg=self.theme["FG"], relief="flat",
                                insertbackground=self.theme["FG"], width=40)
        search_entry.pack(pady=(5, 8))

        box = tk.Text(self.root, bg=self.theme["ENTRY_BG"], fg=self.theme["FG"],
                      width=45, height=10, relief="flat")
        box.pack(pady=8)

        def refresh_display(*args):
            box.config(state="normal")
            box.delete("1.0", "end")
            query = search_var.get().lower().strip()
            entries = self.vault_data.get("entries", [])
            results = [e for e in entries if query in e["name"].lower() or query in e["username"].lower()]
            if not results:
                box.insert("1.0", "No matching entries found.")
            else:
                for e in results:
                    box.insert("end", f"{e['name']} — {e['username']}\n")
            box.config(state="disabled")

        refresh_display()
        search_var.trace_add("write", refresh_display)

        tk.Button(self.root, text="Add New Entry", bg=self.theme["ACCENT"], fg="white",
                  relief="flat", command=self.prompt_add_entry).pack(pady=(4, 6))

        tk.Button(self.root, text="View / Copy Password", bg=self.theme["ENTRY_BG"], fg=self.theme["ACCENT"],
                  relief="flat", command=self.prompt_view_password).pack(pady=(4, 6))

        tk.Button(self.root, text="Close", bg=self.theme["ACCENT"], fg="white",
                  relief="flat", command=self.root.quit).pack(pady=10)

        # Theme toggle button
        tk.Button(self.root,
                  text=f"Switch to {'Light' if self.theme_mode == 'dark' else 'Dark'} Mode",
                  bg=self.theme["ENTRY_BG"], fg=self.theme["ACCENT"], relief="flat",
                  command=self.toggle_theme).pack(pady=(4, 8))

        # Status bar (entry count + last updated)
        entry_count = len(self.vault_data.get("entries", []))
        created_time = self.vault_data.get("created", "Unknown")
        status_text = f"Entries: {entry_count}   |   Vault created: {created_time}"

        status_bar = tk.Label(
            self.root,
            text=status_text,
            bg=self.theme["ENTRY_BG"],
            fg=self.theme["FG"],
            anchor="w",
            font=("Segoe UI", 9)
        )
        status_bar.pack(fill="x", side="bottom", pady=(6, 2))

    # ------------------------------
    def prompt_add_entry(self):
        win = tk.Toplevel(self.root)
        win.title("Add New Entry")
        win.config(bg=self.theme["BG"])
        win.geometry("360x240")

        tk.Label(win, text="Add a New Password Entry",
                 bg=self.theme["BG"], fg=self.theme["FG"], font=("Segoe UI", 12, "bold")).pack(pady=8)

        fields = {}
        for label in ["Site / Service", "Username / Email", "Password"]:
            tk.Label(win, text=label + ":", bg=self.theme["BG"], fg=self.theme["FG"]).pack()
            entry = tk.Entry(win, bg=self.theme["ENTRY_BG"], fg=self.theme["FG"],
                             relief="flat", insertbackground=self.theme["FG"], width=30)
            entry.pack(pady=4)
            fields[label] = entry

        def save_entry():
            site = fields["Site / Service"].get()
            username = fields["Username / Email"].get()
            password = fields["Password"].get()
            if not site or not username or not password:
                messagebox.showerror("Error", "All fields are required.")
                return

            new_entry = {"name": site, "username": username, "password": password}
            self.vault_data["entries"].append(new_entry)

            plaintext = json.dumps(self.vault_data, indent=2).encode("utf-8")
            envelope = create_vault_envelope(password=self.master_password, plaintext_blob=plaintext)
            VAULT_FILE.write_text(envelope)

            messagebox.showinfo("Saved", f"Added new entry for {site}.")
            win.destroy()
            self.show_vault_screen()

        tk.Button(win, text="Save Entry", bg=self.theme["ACCENT"], fg="white",
                  relief="flat", command=save_entry).pack(pady=10)

    # ------------------------------
    def prompt_view_password(self):
        entries = self.vault_data.get("entries", [])
        if not entries:
            messagebox.showinfo("No Entries", "No saved passwords yet.")
            return

        win = tk.Toplevel(self.root)
        win.title("View / Copy Password")
        win.config(bg=self.theme["BG"])
        win.geometry("400x280")

        tk.Label(win, text="Select a site to view password:",
                 bg=self.theme["BG"], fg=self.theme["FG"], font=("Segoe UI", 11, "bold")).pack(pady=10)

        site_names = [e["name"] for e in entries]
        selected = tk.StringVar(win)
        selected.set(site_names[0])

        dropdown = tk.OptionMenu(win, selected, *site_names)
        dropdown.config(bg=self.theme["ENTRY_BG"], fg=self.theme["FG"], width=25)
        dropdown.pack(pady=10)

        pw_frame = tk.Frame(win, bg=self.theme["BG"])
        pw_frame.pack(pady=10)

        tk.Label(pw_frame, text="Password:", bg=self.theme["BG"], fg=self.theme["FG"]).grid(row=0, column=0, padx=5)

        pw_var = tk.StringVar()
        pw_entry = tk.Entry(pw_frame, textvariable=pw_var, show="*", bg=self.theme["ENTRY_BG"],
                            fg=self.theme["FG"], relief="flat", width=25,
                            insertbackground=self.theme["FG"])
        pw_entry.grid(row=0, column=1)

        def toggle_visibility():
            if pw_entry.cget("show") == "*":
                pw_entry.config(show="")
                eye_btn.config(text="🙈")
            else:
                pw_entry.config(show="*")
                eye_btn.config(text="👁️")

        eye_btn = tk.Button(pw_frame, text="👁️", bg=self.theme["BG"], fg=self.theme["FG"],
                            relief="flat", command=toggle_visibility, cursor="hand2")
        eye_btn.grid(row=0, column=2, padx=5)

        def load_password(*args):
            site = selected.get()
            entry = next((e for e in entries if e["name"] == site), None)
            pw_var.set(entry["password"] if entry else "")

        selected.trace_add("write", load_password)
        load_password()

        def copy_to_clipboard():
            site = selected.get()
            entry = next((e for e in entries if e["name"] == site), None)
            if not entry:
                return
            self.root.clipboard_clear()
            self.root.clipboard_append(entry["password"])
            self.root.update()
            messagebox.showinfo("Copied", f"Password for {site} copied to clipboard.\nIt will clear in 10 seconds.")
            self.root.after(10000, lambda: self.root.clipboard_clear())

        tk.Button(win, text="Copy to Clipboard", bg=self.theme["ACCENT"], fg="white",
                  relief="flat", command=copy_to_clipboard).pack(pady=10)

    # ------------------------------
    def toggle_theme(self):
        # Switch theme
        self.theme_mode = "light" if self.theme_mode == "dark" else "dark"
        self.theme = THEMES[self.theme_mode]

        # Save preference to config file
        CONFIG_FILE.write_text(json.dumps({"theme": self.theme_mode}, indent=2))

        # Rebuild the current screen
        if self.vault_data:
            self.show_vault_screen()
        else:
            self.build_unlock_screen()



# ------------------------------
def main():
    root = tk.Tk()
    app = VaultApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
