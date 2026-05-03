import tkinter as tk
from tkinter import filedialog, messagebox
import requests
import os
import threading

from crypto import *
from telegram_sender import send_file

SERVER = "http://127.0.0.1:8000"
PRIVATE_KEY_FILE = "private_key.pem"


class App:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Telegram Sender")
        self.root.geometry("600x400")

        # FIX для macOS Retina
        self.root.tk.call('tk', 'scaling', 2.0)

        self.private_key, self.public_key = self.load_or_generate_keys()

        self.build_ui()

    def build_ui(self):
        frame = tk.Frame(self.root)
        frame.pack(padx=20, pady=20, fill="both", expand=True)

        # окно регистрации
        tk.Label(frame, text="Username").grid(row=0, column=0, sticky="w")
        self.username_entry = tk.Entry(frame)
        self.username_entry.grid(row=0, column=1, sticky="ew")

        tk.Label(frame, text="Chat ID").grid(row=1, column=0, sticky="w")
        self.chat_id_entry = tk.Entry(frame)
        self.chat_id_entry.grid(row=1, column=1, sticky="ew")

        tk.Button(frame, text="Register", command=self.register).grid(row=2, column=0, columnspan=2, pady=10)

        # Окно (Отправить)
        tk.Label(frame, text="Send to username").grid(row=3, column=0, sticky="w")
        self.target_entry = tk.Entry(frame)
        self.target_entry.grid(row=3, column=1, sticky="ew")

        tk.Button(frame, text="Send File", command=self.send_file_threaded).grid(row=4, column=0, columnspan=2, pady=10)

        # Окно (Получить)
        tk.Button(frame, text="Decrypt File", command=self.receive_file).grid(row=5, column=0, columnspan=2, pady=10)

        # статус
        self.status = tk.Label(frame, text="Ready", anchor="w")
        self.status.grid(row=6, column=0, columnspan=2, sticky="ew")

        frame.columnconfigure(1, weight=1)

    def update_status(self, text):
        self.status.config(text=text)
        self.root.update()

    # генерация ключей
    def load_or_generate_keys(self):
        if os.path.exists(PRIVATE_KEY_FILE):
            with open(PRIVATE_KEY_FILE, "rb") as f:
                priv = load_private(f.read())
            return priv, priv.public_key()

        priv, pub = generate_rsa()
        with open(PRIVATE_KEY_FILE, "wb") as f:
            f.write(serialize_private(priv))
        return priv, pub

    # регистрация
    def register(self):
        username = self.username_entry.get()
        chat_id = self.chat_id_entry.get()

        if not username or not chat_id:
            messagebox.showerror("Error", "Fill all fields")
            return

        try:
            requests.post(SERVER + "/register", json={
                "username": username,
                "public_key": serialize_public(self.public_key),
                "chat_id": chat_id
            })
            self.update_status("Registered successfully")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    # отправка
    def send_file_threaded(self):
        threading.Thread(target=self.send_file, daemon=True).start()

    def send_file(self):
        target = self.target_entry.get()

        path = filedialog.askopenfilename()
        if not path:
            return

        self.update_status("Getting user data...")

        r = requests.get(SERVER + "/user/" + target)
        data = r.json()

        if "error" in data:
            messagebox.showerror("Error", "User not found")
            return

        pub = load_public(data["public_key"])
        chat_id = data["chat_id"]

        session_key = generate_session_key()

        with open(path, "rb") as f:
            raw = f.read()

        encrypted = encrypt_file(raw, session_key)
        enc_key = rsa_encrypt(pub, session_key)

        output = "out.bin"
        with open(output, "wb") as f:
            f.write(enc_key + b":::" + encrypted)

        self.update_status("Sending to Telegram...")
        send_file(output, chat_id)

        self.update_status("Sent!")

    # получение
    def receive_file(self):
        path = filedialog.askopenfilename()
        if not path:
            return

        with open(path, "rb") as f:
            data = f.read()

        enc_key, encrypted = data.split(b":::")

        session_key = rsa_decrypt(self.private_key, enc_key)
        decrypted = decrypt_file(encrypted, session_key)

        out = "decrypted.file"
        with open(out, "wb") as f:
            f.write(decrypted)

        self.update_status("Decrypted!")
        messagebox.showinfo("Done", f"Saved as {out}")


if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()