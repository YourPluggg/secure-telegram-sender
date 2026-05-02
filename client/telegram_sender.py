from telegram import Bot
import os
import json

CONFIG_FILE = "telegram_config.json"


def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    return {}


def save_config(config):
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2)


def send_file(file_path, chat_id=None):
    config = load_config()

    # Пытаемся получить chat_id
    if not chat_id:
        chat_id = config.get("chat_id")
        if not chat_id:
            print(f"\nНе указан CHAT_ID для отправки в Telegram")
            print(f"Как получить chat_id:")
            print(f"1. Напишите боту https://t.me/userinfobot")
            print(f"2. Он отправит ваш ID")
            chat_id = input("Введите ваш CHAT_ID: ").strip()

            # Сохраняем
            config["chat_id"] = chat_id
            save_config(config)
            print(f"CHAT_ID сохранён в {CONFIG_FILE}")

    # Читаем токен из переменной окружения или файла
    TOKEN = config.get("bot_token") or os.getenv("TELEGRAM_BOT_TOKEN")

    if not TOKEN:
        TOKEN = input("Введите токен Telegram бота: ").strip()
        save = input("Сохранить токен для следующих сеансов? (y/n): ").lower()
        if save == 'y':
            config["bot_token"] = TOKEN
            save_config(config)

    try:
        bot = Bot(token=TOKEN)
        with open(file_path, "rb") as f:
            bot.send_document(chat_id=chat_id, document=f)
        print(f"Файл {file_path} отправлен в Telegram (chat_id: {chat_id})")
        return True
    except Exception as e:
        print(f"Ошибка отправки в Telegram: {e}")
        return False


# тест
if __name__ == "__main__":
    send_file("out.bin")