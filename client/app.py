import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
import requests
import os
from crypto import *
from telegram_sender import send_file
import threading

SERVER = "http://127.0.0.1:8000"
PRIVATE_KEY_FILE = "private_key.pem"


class App:
    def __init__(self, root):
        self.root = root
        root.title("Secure Telegram Sender")
        root.geometry("500x400")

        # Загружаем или генерируем ключи
        self.private_key, self.public_key = self.load_or_generate_keys()

        self.create_widgets()

    #Загружает существующий приватный ключ или генерирует новый
    def load_or_generate_keys(self):
        if os.path.exists(PRIVATE_KEY_FILE):
            try:
                with open(PRIVATE_KEY_FILE, "rb") as f:
                    private_pem = f.read()
                private_key = load_private(private_pem)
                public_key = private_key.public_key()
                print("Ключи загружены из файла")
                return private_key, public_key
            except Exception as e:
                print(f"Ошибка загрузки ключей: {e}")
                # Если не загрузились - генерируем новые
                return self.generate_and_save_keys()
        else:
            print("Файл с ключами не найден, генерируем новые")
            return self.generate_and_save_keys()

    #Генерируем новую RSA-пару и сохраняет приватный ключ
    def generate_and_save_keys(self):
        private_key, public_key = generate_rsa()

        # Сохраняем приватный ключ
        with open(PRIVATE_KEY_FILE, "wb") as f:
            f.write(serialize_private(private_key))

        print(f" Сгенерированы новые ключи. Приватный ключ сохранён в {PRIVATE_KEY_FILE}")
        return private_key, public_key

    def create_widgets(self):
        # Рамка для регистрации
        frame_reg = tk.LabelFrame(self.root, text="Регистрация", padx=10, pady=10)
        frame_reg.pack(fill="x", padx=10, pady=5)

        tk.Label(frame_reg, text="Ваш username:").pack(side="left")
        self.username_entry = tk.Entry(frame_reg, width=20)
        self.username_entry.pack(side="left", padx=5)

        tk.Button(frame_reg, text="Зарегистрировать ключ", command=self.register).pack(side="left", padx=5)

        # Статус регистрации
        self.register_status = tk.Label(frame_reg, text="", fg="gray")
        self.register_status.pack(side="left", padx=5)

        # Рамка для отправки
        frame_send = tk.LabelFrame(self.root, text="Отправка файла", padx=10, pady=10)
        frame_send.pack(fill="x", padx=10, pady=5)

        tk.Label(frame_send, text="Кому (username):").pack(side="left")
        self.target_entry = tk.Entry(frame_send, width=20)
        self.target_entry.pack(side="left", padx=5)

        tk.Button(frame_send, text="Выбрать и отправить файл", command=self.send_file_threaded).pack(side="left",
                                                                                                     padx=5)

        # Прогресс отправки
        self.send_progress = ttk.Progressbar(frame_send, mode='indeterminate', length=150)

        # Рамка для получения
        frame_recv = tk.LabelFrame(self.root, text="Получение и расшифровка", padx=10, pady=10)
        frame_recv.pack(fill="x", padx=10, pady=5)

        tk.Button(frame_recv, text="Выбрать и расшифровать файл", command=self.receive_file).pack(side="left")

        # Статус-бар
        self.status_bar = tk.Label(self.root, text="Готов", relief="sunken", anchor="w")
        self.status_bar.pack(side="bottom", fill="x")

        # Информация о ключах
        frame_info = tk.LabelFrame(self.root, text="Информация", padx=10, pady=10)
        frame_info.pack(fill="both", expand=True, padx=10, pady=5)

        pub_key_str = serialize_public(self.public_key)[:50] + "..."
        tk.Label(frame_info, text=f"Ваш публичный ключ (первые 50 символов):", wraplength=450, justify="left").pack(
            anchor="w")
        tk.Label(frame_info, text=pub_key_str, font=("Courier", 8), fg="blue", wraplength=450).pack(anchor="w")

        private_exists = os.path.exists(PRIVATE_KEY_FILE)
        tk.Label(frame_info, text=f"Приватный ключ сохранён: {'Да' if private_exists else 'Нет'}",
                 fg="green" if private_exists else "red").pack(anchor="w")
        tk.Label(frame_info, text=f"Путь к приватному ключу: {PRIVATE_KEY_FILE}", font=("Courier", 8)).pack(anchor="w")

    def update_status(self, message, color="black"):
        self.status_bar.config(text=message, fg=color)
        self.root.update()

    def register(self):
        username = self.username_entry.get().strip()
        if not username:
            messagebox.showerror("Ошибка", "Введите username")
            return

        self.update_status(f"Регистрация пользователя {username}...", "blue")
        self.register_status.config(text="Регистрация...", fg="orange")

        try:
            pub = serialize_public(self.public_key)
            response = requests.post(
                SERVER + "/register",
                json={"username": username, "public_key": pub},
                timeout=5
            )

            if response.status_code == 200:
                self.update_status(f"Пользователь {username} зарегистрирован", "green")
                self.register_status.config(text="Зарегистрирован", fg="green")
                messagebox.showinfo("Успех", f"Пользователь {username} зарегистрирован!")
            else:
                self.update_status(f"Ошибка регистрации: {response.text}", "red")
                self.register_status.config(text="Ошибка", fg="red")

        except requests.exceptions.RequestException as e:
            self.update_status(f"Ошибка соединения: {e}", "red")
            self.register_status.config(text="Ошибка сети", fg="red")
            messagebox.showerror("Ошибка", f"Не удалось подключиться к серверу: {e}")

    #отправка файла в отдельном потоке
    def send_file_threaded(self):
        thread = threading.Thread(target=self.send_file, daemon=True)
        thread.start()

    #шифруем и отправляем
    def send_file(self):
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showerror("Ошибка", "Введите получателя")
            return

        # Выбор файла
        path = filedialog.askopenfilename(title="Выберите файл для отправки")
        if not path:
            return

        #показ прогресса
        self.send_progress.pack(side="left", padx=5)
        self.send_progress.start(10)
        self.update_status(f"Шифрование файла {os.path.basename(path)}...", "blue")

        try:
            # Получаем публичный ключ получателя
            self.update_status(f"Запрос ключа пользователя {target}...", "blue")
            r = requests.get(SERVER + "/key/" + target, timeout=5)

            if r.status_code != 200 or not r.json().get("public_key"):
                self.update_status(f"Пользователь {target} не найден", "red")
                messagebox.showerror("Ошибка", f"Пользователь {target} не зарегистрирован")
                self.send_progress.stop()
                self.send_progress.pack_forget()
                return

            pub = load_public(r.json()["public_key"])

            # Генерируем сессионный ключ
            session_key = generate_session_key()

            # Шифруем файл
            with open(path, "rb") as f:
                data = f.read()

            self.update_status(f"Шифрование AES (файл: {len(data)} байт)...", "blue")
            encrypted = encrypt_file(data, session_key)

            # Шифруем ключ через RSA
            enc_key = rsa_encrypt(pub, session_key)

            # Сохраняем в файл
            output_path = "out.bin"
            with open(output_path, "wb") as f:
                f.write(enc_key + b"---KEY---" + encrypted)

            # Отправляем через Telegram
            self.update_status(f"Отправка через Telegram...", "blue")
            send_file(output_path)  # Нужен chat_id

            self.send_progress.stop()
            self.send_progress.pack_forget()

            self.update_status(f"Файл успешно зашифрован и отправлен! Сохранён как {output_path}", "green")
            messagebox.showinfo("Успех", f"Файл отправлен!\nЗашифрованный файл сохранён как {output_path}")

        except requests.exceptions.RequestException as e:
            self.update_status(f"Ошибка сети: {e}", "red")
            messagebox.showerror("Ошибка", f"Не удалось подключиться к серверу: {e}")
            self.send_progress.stop()
            self.send_progress.pack_forget()
        except Exception as e:
            self.update_status(f"Ошибка: {e}", "red")
            messagebox.showerror("Ошибка", f"Произошла ошибка: {e}")
            self.send_progress.stop()
            self.send_progress.pack_forget()

    def receive_file(self):
        #выбор и расшифровка
        path = filedialog.askopenfilename(
            title="Выберите зашифрованный файл (out.bin)",
            filetypes=[("Binary files", "*.bin"), ("All files", "*.*")]
        )

        if not path:
            return

        self.update_status(f"Расшифровка файла {os.path.basename(path)}...", "blue")

        try:
            with open(path, "rb") as f:
                data = f.read()

            # Разделяем ключ и зашифрованные данные
            if b"---KEY---" not in data:
                messagebox.showerror("Ошибка", "Неверный формат файла (нет разделителя KEY)")
                return

            enc_key, encrypted = data.split(b"---KEY---")

            # Расшифровываем session_key своим приватным ключом
            self.update_status(f"Расшифровка сессионного ключа RSA...", "blue")
            session_key = rsa_decrypt(self.private_key, enc_key)

            # Расшифровываем файл
            self.update_status(f"Расшифровка файла AES...", "blue")
            decrypted = decrypt_file(encrypted, session_key)

            output_path = "decrypted_" + os.path.basename(path).replace(".bin", "") + ".file"
            with open(output_path, "wb") as f:
                f.write(decrypted)

            self.update_status(f"Файл успешно расшифрован! Сохранён как {output_path}", "green")

            if messagebox.askyesno("Успех", f"Файл расшифрован и сохранён как {output_path}\nОткрыть папку с файлом?"):
                os.startfile(os.path.dirname(os.path.abspath(output_path)))

        except Exception as e:
            self.update_status(f"Ошибка расшифровки: {e}", "red")
            messagebox.showerror("Ошибка", f"Не удалось расшифровать файл:\n{e}")


if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()