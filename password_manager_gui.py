import tkinter as tk
from tkinter import messagebox, simpledialog
import sqlite3
import os
import base64
import hashlib
from cryptography.fernet import Fernet, InvalidToken

DB_FILE = 'passwords.db'
KEY_FILE = 'key.bin'

# --- Helper Functions ---
def get_key(master_password):
    password_bytes = master_password.encode()
    key = hashlib.sha256(password_bytes).digest()
    return base64.urlsafe_b64encode(key)

def load_or_create_key(master_password):
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, 'rb') as f:
            key = f.read()
    else:
        key = get_key(master_password)
        with open(KEY_FILE, 'wb') as f:
            f.write(key)
    return key

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS passwords (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    service TEXT NOT NULL,
                    username TEXT NOT NULL,
                    password TEXT NOT NULL
                )''')
    conn.commit()
    conn.close()

def add_password(fernet, service, username, password):
    enc_password = fernet.encrypt(password.encode()).decode()
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('INSERT INTO passwords (service, username, password) VALUES (?, ?, ?)',
              (service, username, enc_password))
    conn.commit()
    conn.close()

def get_passwords(fernet):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('SELECT service, username, password FROM passwords')
    rows = c.fetchall()
    conn.close()
    decrypted = []
    for service, username, enc_password in rows:
        try:
            dec_password = fernet.decrypt(enc_password.encode()).decode()
        except InvalidToken:
            dec_password = '[Decryption failed]'
        decrypted.append((service, username, dec_password))
    return decrypted

# --- GUI Classes ---
class PasswordManagerApp:
    def __init__(self, root, fernet):
        self.root = root
        self.fernet = fernet
        self.root.title('Secure Password Manager')
        self.root.geometry('400x400')
        self.create_widgets()
        self.refresh_passwords()

    def create_widgets(self):
        self.frame = tk.Frame(self.root)
        self.frame.pack(pady=10)

        self.add_btn = tk.Button(self.frame, text='Add Password', command=self.add_password_dialog)
        self.add_btn.pack(side=tk.LEFT, padx=5)

        self.refresh_btn = tk.Button(self.frame, text='Refresh', command=self.refresh_passwords)
        self.refresh_btn.pack(side=tk.LEFT, padx=5)

        self.listbox = tk.Listbox(self.root, width=55)
        self.listbox.pack(pady=10, fill=tk.BOTH, expand=True)

    def add_password_dialog(self):
        service = simpledialog.askstring('Service', 'Enter service name:')
        if not service:
            return
        username = simpledialog.askstring('Username', 'Enter username:')
        if not username:
            return
        password = simpledialog.askstring('Password', 'Enter password:', show='*')
        if not password:
            return
        add_password(self.fernet, service, username, password)
        messagebox.showinfo('Success', 'Password added successfully!')
        self.refresh_passwords()

    def refresh_passwords(self):
        self.listbox.delete(0, tk.END)
        passwords = get_passwords(self.fernet)
        if not passwords:
            self.listbox.insert(tk.END, 'No passwords stored.')
        else:
            for service, username, password in passwords:
                self.listbox.insert(tk.END, f'Service: {service} | Username: {username} | Password: {password}')

class MasterPasswordDialog:
    def __init__(self, root):
        self.root = root
        self.master_password = None
        self.dialog = tk.Toplevel(root)
        self.dialog.title('Master Password')
        self.dialog.geometry('300x120')
        self.dialog.grab_set()
        tk.Label(self.dialog, text='Enter Master Password:').pack(pady=10)
        self.entry = tk.Entry(self.dialog, show='*', width=25)
        self.entry.pack(pady=5)
        self.entry.focus()
        self.ok_btn = tk.Button(self.dialog, text='OK', command=self.on_ok)
        self.ok_btn.pack(pady=5)
        self.dialog.protocol('WM_DELETE_WINDOW', self.on_close)
        self.root.wait_window(self.dialog)

    def on_ok(self):
        self.master_password = self.entry.get()
        self.dialog.destroy()

    def on_close(self):
        self.master_password = None
        self.dialog.destroy()

# --- Main Application ---
def main():
    init_db()
    root = tk.Tk()
    # Prompt for master password
    mp_dialog = MasterPasswordDialog(root)
    master_password = mp_dialog.master_password
    if not master_password:
        root.destroy()
        return
    key = load_or_create_key(master_password)
    fernet = Fernet(key)
    # Test decryption to check if master password is correct
    try:
        # Try to decrypt one password if exists
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('SELECT password FROM passwords LIMIT 1')
        row = c.fetchone()
        conn.close()
        if row:
            fernet.decrypt(row[0].encode())
    except InvalidToken:
        messagebox.showerror('Error', 'Wrong master password!')
        root.destroy()
        return
    PasswordManagerApp(root, fernet)
    root.mainloop()

if __name__ == '__main__':
    main() 