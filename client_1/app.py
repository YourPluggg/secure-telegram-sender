"""
app.py — GUI-клиент Secure Telegram Sender v2.
Кросс-платформенный: macOS, Windows, Linux.

"""

import base64
import os
import platform
import tempfile
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk

import requests

from crypto import (
    decrypt_file,
    encrypt_file,
    generate_rsa,
    generate_session_key,
    load_private,
    load_public,
    pack_bundle,
    rsa_decrypt,
    rsa_encrypt,
    serialize_private,
    serialize_public,
    sign_data,
    unpack_bundle,
    verify_signature,
)

SERVER = "https://secure-telegram-sender-production.up.railway.app"
PRIVATE_KEY_FILE = "private_key.pem"
TOKEN_FILE = "auth_token.txt"


# ── DPI ──────────────────────────────────────────────────────────────────────

def _configure_dpi(root: tk.Tk) -> None:
    system = platform.system()
    if system == "Darwin":
        try:
            root.tk.call("tk", "scaling", 2.0)
        except Exception:
            pass
    elif system == "Windows":
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass
        try:
            root.tk.call("tk", "scaling", root.winfo_fpixels("1i") / 72)
        except Exception:
            pass


# ── Приложение ────────────────────────────────────────────────────────────────

class App:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Secure Telegram Sender")
        self.root.geometry("520x460")
        self.root.resizable(False, False)

        _configure_dpi(root)

        self._token: str = self._load_token()
        self.private_key, self.public_key = self._load_or_generate_keys()
        self._build_ui()

    # ── Токен ──────────────────────────────────────────────────────────────

    def _load_token(self) -> str:
        if os.path.exists(TOKEN_FILE):
            with open(TOKEN_FILE, "r") as f:
                return f.read().strip()
        return ""

    def _save_token(self, token: str) -> None:
        self._token = token
        with open(TOKEN_FILE, "w") as f:
            f.write(token)

    # ── Ключи с паролем ───────────────────────────────────────────────────

    def _ask_password(self, title: str, prompt: str) -> str | None:
        """Диалог ввода пароля. Возвращает строку или None если отменено."""
        pwd = simpledialog.askstring(title, prompt, show="*", parent=self.root)
        return pwd

    def _load_or_generate_keys(self):
        if os.path.exists(PRIVATE_KEY_FILE):
            return self._load_keys_with_password()
        return self._generate_keys_with_password()

    def _load_keys_with_password(self):
        """Загружает ключи с паролем. При неверном пароле предлагает повторить."""
        for attempt in range(3):
            pwd = self._ask_password(
                "Пароль ключа",
                f"Введите пароль для расшифровки приватного ключа"
                f"{' (попытка ' + str(attempt + 1) + '/3)' if attempt > 0 else ''}:",
            )
            if pwd is None:
                # Пользователь нажал Отмена
                messagebox.showerror(
                    "Ошибка", "Без пароля приложение не может работать."
                )
                self.root.destroy()
                raise SystemExit

            try:
                with open(PRIVATE_KEY_FILE, "rb") as f:
                    priv = load_private(f.read(), password=pwd.encode() if pwd else None)
                return priv, priv.public_key()
            except Exception:
                if attempt == 2:
                    messagebox.showerror(
                        "Ошибка",
                        "Неверный пароль. Приложение закрывается.\n"
                        "Если вы забыли пароль — удалите private_key.pem "
                        "и зарегистрируйтесь заново.",
                    )
                    self.root.destroy()
                    raise SystemExit
                continue

    def _generate_keys_with_password(self):
        """Генерирует новую пару ключей, запрашивает пароль для защиты."""
        messagebox.showinfo(
            "Первый запуск",
            "Приватный ключ не найден.\n"
            "Будет сгенерирована новая пара RSA-2048 ключей.\n\n"
            "Задайте пароль для защиты приватного ключа на диске.\n"
            "Запомните его — без пароля ключ не загрузится.",
        )
        pwd = self._ask_password("Новый пароль", "Задайте пароль для приватного ключа:")
        if pwd is None:
            messagebox.showerror("Ошибка", "Пароль обязателен.")
            self.root.destroy()
            raise SystemExit

        pwd2 = self._ask_password("Подтверждение", "Повторите пароль:")
        if pwd != pwd2:
            messagebox.showerror("Ошибка", "Пароли не совпадают. Перезапустите приложение.")
            self.root.destroy()
            raise SystemExit

        priv, pub = generate_rsa()
        with open(PRIVATE_KEY_FILE, "wb") as f:
            f.write(serialize_private(priv, password=pwd.encode() if pwd else None))
        return priv, pub

    # ── UI ────────────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        nb = ttk.Notebook(self.root)
        nb.pack(fill="both", expand=True, padx=10, pady=10)

        tab_s = ttk.Frame(nb)
        nb.add(tab_s, text="Настройки")
        self._build_settings_tab(tab_s)

        tab_send = ttk.Frame(nb)
        nb.add(tab_send, text="Отправить")
        self._build_send_tab(tab_send)

        tab_recv = ttk.Frame(nb)
        nb.add(tab_recv, text="Расшифровать")
        self._build_recv_tab(tab_recv)

        self.status_var = tk.StringVar(value="Готов")
        ttk.Label(
            self.root, textvariable=self.status_var, relief="sunken", anchor="w"
        ).pack(fill="x", side="bottom")

        self.progress = ttk.Progressbar(self.root, mode="indeterminate")
        self.progress.pack(fill="x", side="bottom")

    def _build_settings_tab(self, parent: ttk.Frame) -> None:
        pad = {"padx": 15, "pady": 8}

        ttk.Label(parent, text="Регистрация",
                  font=("", 11, "bold")).grid(
            row=0, column=0, columnspan=2, sticky="w", padx=15, pady=(15, 5))
        ttk.Separator(parent, orient="horizontal").grid(
            row=1, column=0, columnspan=2, sticky="ew", padx=15, pady=(0, 10))

        ttk.Label(parent, text="Имя пользователя:").grid(
            row=2, column=0, sticky="w", **pad)
        self.username_entry = ttk.Entry(parent, width=30)
        self.username_entry.grid(row=2, column=1, sticky="ew", **pad)

        ttk.Label(parent, text="Chat ID:").grid(row=3, column=0, sticky="w", **pad)
        self.chat_id_entry = ttk.Entry(parent, width=30)
        self.chat_id_entry.grid(row=3, column=1, sticky="ew", **pad)

        ttk.Label(
            parent,
            text="Узнайте Chat ID у @userinfobot в Telegram",
            foreground="gray",
        ).grid(row=4, column=1, sticky="w", padx=15, pady=(0, 8))

        # Статус токена
        self.token_status_var = tk.StringVar(
            value="Токен: есть" if self._token else "Токен: нет (нужна регистрация)"
        )
        ttk.Label(parent, textvariable=self.token_status_var,
                  foreground="green" if self._token else "red").grid(
            row=5, column=0, columnspan=2, padx=15, pady=(0, 8))

        ttk.Button(
            parent, text="Зарегистрироваться", command=self._register
        ).grid(row=6, column=0, columnspan=2, pady=15)

        # Смена ключа
        ttk.Separator(parent, orient="horizontal").grid(
            row=7, column=0, columnspan=2, sticky="ew", padx=15, pady=(0, 8))
        ttk.Label(parent, text="Сменить пару ключей (с подтверждением):",
                  foreground="gray").grid(
            row=8, column=0, columnspan=2, sticky="w", padx=15)
        ttk.Button(
            parent, text="Обновить ключ", command=self._rekey
        ).grid(row=9, column=0, columnspan=2, pady=8)

        parent.columnconfigure(1, weight=1)

    def _build_send_tab(self, parent: ttk.Frame) -> None:
        ttk.Label(parent, text="Отправка зашифрованного файла",
                  font=("", 11, "bold")).pack(anchor="w", padx=15, pady=(15, 5))
        ttk.Separator(parent, orient="horizontal").pack(
            fill="x", padx=15, pady=(0, 10))

        frame = ttk.Frame(parent)
        frame.pack(fill="x", padx=15, pady=8)
        ttk.Label(frame, text="Получатель:").pack(side="left", padx=(0, 10))
        self.target_entry = ttk.Entry(frame, width=28)
        self.target_entry.pack(side="left", fill="x", expand=True)

        ttk.Label(
            parent,
            text="Укажите имя зарегистрированного пользователя",
            foreground="gray",
        ).pack(anchor="w", padx=15, pady=(0, 15))

        ttk.Button(
            parent, text="Выбрать файл и отправить",
            command=self._send_file_threaded,
        ).pack(pady=10)

        info = ttk.LabelFrame(parent, text="Схема защиты", padding=10)
        info.pack(fill="x", padx=15, pady=10)
        ttk.Label(
            info,
            text="1. Шифрование: AES-256-GCM\n"
                 "2. Обмен ключом: RSA-OAEP-SHA256\n"
                 "3. Подпись: RSA-PSS-SHA256 (encrypt-then-sign)\n"
                 "4. Доставка: через сервер по JWT-токену",
            justify="left",
        ).pack(anchor="w")

    def _build_recv_tab(self, parent: ttk.Frame) -> None:
        ttk.Label(parent, text="Расшифровка файла",
                  font=("", 11, "bold")).pack(anchor="w", padx=15, pady=(15, 5))
        ttk.Separator(parent, orient="horizontal").pack(
            fill="x", padx=15, pady=(0, 10))

        ttk.Label(
            parent, text="Выберите .bin файл, полученный из Telegram:"
        ).pack(anchor="w", padx=15, pady=(5, 10))

        ttk.Button(
            parent, text="Выбрать файл и расшифровать",
            command=self._receive_file,
        ).pack(pady=10)

        sig_frame = ttk.LabelFrame(
            parent, text="Проверка подписи (необязательно)", padding=10)
        sig_frame.pack(fill="x", padx=15, pady=15)
        ttk.Label(sig_frame, text="Имя отправителя:").pack(anchor="w", pady=(0, 5))
        self.sender_entry = ttk.Entry(sig_frame, width=30)
        self.sender_entry.pack(fill="x", pady=(0, 5))
        ttk.Label(
            sig_frame,
            text="Оставьте пустым — подпись не будет проверена",
            foreground="gray",
        ).pack(anchor="w")

    # ── Статус ────────────────────────────────────────────────────────────

    def _set_status(self, text: str) -> None:
        self.status_var.set(text)
        self.root.update_idletasks()

    def _start_progress(self) -> None:
        self.progress.start(12)

    def _stop_progress(self) -> None:
        self.progress.stop()

    # ── Регистрация ───────────────────────────────────────────────────────

    def _register(self) -> None:
        username = self.username_entry.get().strip()
        chat_id = self.chat_id_entry.get().strip()

        if not username or not chat_id:
            messagebox.showerror("Ошибка", "Заполните имя пользователя и Chat ID")
            return
        if not chat_id.lstrip("-").isdigit():
            messagebox.showerror("Ошибка", "Chat ID должен быть числом")
            return

        try:
            r = requests.post(
                SERVER + "/register",
                json={
                    "username": username,
                    "public_key": serialize_public(self.public_key),
                    "chat_id": chat_id,
                },
                timeout=10,
            )
            if r.status_code == 409:
                # Пользователь уже существует — предлагаем обновление с подписью
                messagebox.showinfo(
                    "Уже зарегистрирован",
                    f"Пользователь «{username}» уже существует.\n"
                    "Используйте кнопку «Обновить ключ» для смены ключа.",
                )
                return
            r.raise_for_status()
            data = r.json()
            self._save_token(data["token"])
            self.token_status_var.set("Токен: получен")
            self._set_status(f"Зарегистрирован как «{username}»")
            messagebox.showinfo(
                "Готово",
                f"Пользователь «{username}» зарегистрирован.\n"
                f"JWT-токен сохранён (действует 24 часа).",
            )
        except requests.ConnectionError:
            messagebox.showerror(
                "Ошибка",
                "Нет соединения с сервером.\n"
                "Убедитесь, что сервер запущен на http://127.0.0.1:8000",
            )
        except requests.HTTPError as e:
            messagebox.showerror("Ошибка сервера",
                                 f"{e.response.status_code}: {e.response.text}")
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))

    def _rekey(self) -> None:
        """Обновление ключа: подписываем новый публичный ключ старым приватным."""
        username = self.username_entry.get().strip()
        if not username:
            messagebox.showerror("Ошибка", "Введите имя пользователя")
            return

        if not messagebox.askyesno(
            "Смена ключа",
            "Будет сгенерирована новая пара ключей.\n"
            "Старые зашифрованные файлы нельзя будет расшифровать новым ключом.\n\n"
            "Продолжить?",
        ):
            return

        # Сохраняем старый приватный ключ для подписи
        old_private_key = self.private_key

        # Генерируем новую пару
        new_priv, new_pub = generate_rsa()

        # Подписываем новый публичный ключ старым приватным
        new_pub_bytes = serialize_public(new_pub).encode()
        signature = sign_data(old_private_key, new_pub_bytes)
        sig_b64 = base64.b64encode(signature).decode()

        # Запрашиваем новый пароль
        messagebox.showinfo(
            "Новый пароль",
            "Задайте пароль для нового приватного ключа.",
        )
        pwd = self._ask_password("Новый пароль", "Пароль для нового ключа:")
        if pwd is None:
            return
        pwd2 = self._ask_password("Подтверждение", "Повторите пароль:")
        if pwd != pwd2:
            messagebox.showerror("Ошибка", "Пароли не совпадают")
            return

        chat_id = self.chat_id_entry.get().strip() or "0"

        try:
            r = requests.post(
                SERVER + "/register",
                json={
                    "username": username,
                    "public_key": serialize_public(new_pub),
                    "chat_id": chat_id,
                    "old_key_signature": sig_b64,
                },
                timeout=10,
            )
            r.raise_for_status()
            data = r.json()

            # Сохраняем новый ключ
            with open(PRIVATE_KEY_FILE, "wb") as f:
                f.write(serialize_private(new_priv,
                        password=pwd.encode() if pwd else None))
            self.private_key = new_priv
            self.public_key = new_pub

            self._save_token(data["token"])
            self.token_status_var.set("Токен: получен (новый ключ)")
            self._set_status("Ключ обновлён")
            messagebox.showinfo("Готово", "Ключ успешно обновлён на сервере.")
        except requests.HTTPError as e:
            messagebox.showerror("Ошибка", f"{e.response.status_code}: {e.response.text}")
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))

    # ── Отправка ──────────────────────────────────────────────────────────

    def _send_file_threaded(self) -> None:
        if not self._token:
            messagebox.showerror(
                "Нет токена",
                "Вы не зарегистрированы или токен истёк.\n"
                "Перейдите в «Настройки» и зарегистрируйтесь.",
            )
            return
        path = filedialog.askopenfilename(title="Выберите файл для отправки")
        if not path:
            return
        threading.Thread(target=self._send_file, args=(path,), daemon=True).start()

    def _send_file(self, path: str) -> None:
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showerror("Ошибка", "Укажите получателя")
            return

        self._start_progress()
        tmp_path = None
        try:
            self._set_status("Получение публичного ключа...")
            r = requests.get(SERVER + "/user/" + target, timeout=5)
            r.raise_for_status()
            data = r.json()

            pub = load_public(data["public_key"])

            self._set_status("Шифрование и подпись...")
            session_key = generate_session_key()
            with open(path, "rb") as f:
                raw = f.read()

            encrypted = encrypt_file(raw, session_key)
            enc_key = rsa_encrypt(pub, session_key)
            signature = sign_data(self.private_key, encrypted)
            bundle = pack_bundle(enc_key, signature, encrypted, os.path.basename(path))

            with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tmp:
                tmp.write(bundle)
                tmp_path = tmp.name

            self._set_status("Передача на сервер...")
            with open(tmp_path, "rb") as f:
                resp = requests.post(
                    SERVER + "/send",
                    params={"username": target},
                    files={"file": (os.path.basename(path) + ".bin", f,
                                    "application/octet-stream")},
                    headers={"Authorization": f"Bearer {self._token}"},
                    timeout=30,
                )

            if resp.status_code == 401:
                messagebox.showerror(
                    "Токен истёк",
                    "JWT-токен недействителен или истёк.\n"
                    "Зарегистрируйтесь повторно в «Настройках».",
                )
                self._set_status("Ошибка: токен истёк")
                return

            resp.raise_for_status()
            self._set_status(f"Отправлено пользователю «{target}»")
            messagebox.showinfo("Готово", f"Файл отправлен «{target}».")

        except requests.ConnectionError:
            messagebox.showerror("Ошибка", "Нет соединения с сервером")
            self._set_status("Ошибка отправки")
        except requests.HTTPError as e:
            messagebox.showerror("Ошибка сервера",
                                 f"{e.response.status_code}: {e.response.text}")
            self._set_status("Ошибка отправки")
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))
            self._set_status("Ошибка отправки")
        finally:
            self._stop_progress()
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.unlink(tmp_path)
                except Exception:
                    pass

    # ── Расшифровка ───────────────────────────────────────────────────────

    def _receive_file(self) -> None:
        path = filedialog.askopenfilename(
            title="Выберите зашифрованный файл",
            filetypes=[("Binary", "*.bin"), ("Все файлы", "*.*")],
        )
        if not path:
            return

        self._start_progress()
        try:
            with open(path, "rb") as f:
                bundle = f.read()

            enc_key, signature, encrypted, original_filename = unpack_bundle(bundle)

            sender = self.sender_entry.get().strip()
            if sender:
                self._set_status("Проверка подписи...")
                try:
                    r = requests.get(SERVER + "/user/" + sender, timeout=5)
                    r.raise_for_status()
                    sender_pub = load_public(r.json()["public_key"])
                except Exception:
                    messagebox.showerror(
                        "Ошибка",
                        f"Не удалось получить ключ пользователя «{sender}»",
                    )
                    return

                if not verify_signature(sender_pub, encrypted, signature):
                    messagebox.showerror(
                        "Подпись недействительна",
                        f"Файл не подписан пользователем «{sender}».\n"
                        "Возможна подмена или повреждение.\n"
                        "Расшифровка отменена.",
                    )
                    self._set_status("Подпись не прошла проверку")
                    return
                self._set_status("Подпись верна — расшифровка...")
            else:
                self._set_status("Расшифровка...")

            session_key = rsa_decrypt(self.private_key, enc_key)
            decrypted = decrypt_file(encrypted, session_key)

            if original_filename:
                out_path = os.path.join(os.path.dirname(path), original_filename)
            else:
                out_path = os.path.splitext(path)[0] + "_decrypted"
            with open(out_path, "wb") as f:
                f.write(decrypted)

            status = "Сохранено: " + os.path.basename(out_path)
            if sender:
                status += f" | Подпись «{sender}» верна"
            self._set_status(status)
            messagebox.showinfo("Готово", f"Файл сохранён:\n{out_path}")

        except requests.ConnectionError:
            messagebox.showerror("Ошибка", "Нет соединения с сервером")
        except Exception as e:
            messagebox.showerror("Ошибка расшифровки", str(e))
            self._set_status("Ошибка расшифровки")
        finally:
            self._stop_progress()


# ── Запуск ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()