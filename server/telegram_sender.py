import asyncio
import os
from telegram import Bot

async def _send(token: str, chat_id: str, file_path: str, caption: str = ""):
    async with Bot(token=token) as bot:
        with open(file_path, "rb") as f:
            await bot.send_document(
                chat_id=chat_id,
                document=f,
                caption=caption or os.path.basename(file_path),
            )

def send_file(file_path: str, chat_id: str, caption: str = ""):
    token = os.getenv("TELEGRAM_BOT_TOKEN")

    if not token:
        raise ValueError("TELEGRAM_BOT_TOKEN не задан")

    if os.name == "nt":
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

    asyncio.run(_send(token, chat_id, file_path, caption))