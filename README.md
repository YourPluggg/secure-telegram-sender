# 🔐 Secure Telegram Sender

 Secure Telegram Sender
 
Шифрованная отправка файлов через Telegram с использованием RSA + AES-GCM.
 
## Структура проекта
 
```
project/
├── client/
│   ├── app.py              # GUI-клиент
│   ├── crypto.py           # Криптографические примитивы
│   ├── telegram_sender.py  # Отправка через Telegram Bot API
│   └── requirements.txt
└── server/
    ├── main.py             # FastAPI-сервер
    └── requirements.txt
```

---
 
## ⚙️ Требования

* Python 3.10+
* pip
* Telegram аккаунт

---

## Установка
## 1. Клонирование проекта

```bash
git clone <your_repo_url>
cd project
```

---

### 2. Создание виртуального окружения

```bash
python -m venv venv
```

#### Windows:

```bash
venv\Scripts\activate
```

#### Linux / macOS:

```bash
source venv/bin/activate
```

---

## Запуск
### Сервер
```bash
cd server
pip install -r requirements.txt
python main.py
```

---
 
### Клиент
```bash
cd client
pip install -r requirements.txt
python app.py
```
 
На Windows используйте `pip` из venv или `py -m pip`.

---
 
## Настройка
 
1. **Создайте Telegram-бота** через [@BotFather](https://t.me/BotFather), получите токен.
2. **Узнайте свой Chat ID** через [@userinfobot](https://t.me/userinfobot).
3. В клиенте:
   - Вкладка «Настройки»: введите токен бота → «Сохранить токен»
   - Введите имя и Chat ID → «Зарегистрировать»
## Алгоритм работы
 
```
Отправитель:
  1. Получает публичный ключ получателя с сервера
  2. Генерирует случайный AES-256 session key
  3. Шифрует файл: AES-256-GCM(file, session_key)
  4. Шифрует ключ: RSA-OAEP-SHA256(session_key, pub_key)
  5. Упаковывает в бинарный пакет и отправляет в Telegram
 
Получатель:
  1. Скачивает файл из Telegram
  2. Расшифровывает session key своим приватным ключом
  3. Расшифровывает файл через AES-256-GCM (с проверкой целостности)
```