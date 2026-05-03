from fastapi import FastAPI
from pydantic import BaseModel
import sqlite3
import uvicorn

app = FastAPI()

conn = sqlite3.connect("db.sqlite", check_same_thread=False)
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    public_key TEXT,
    chat_id TEXT
)
""")

class User(BaseModel):
    username: str
    public_key: str
    chat_id: str


@app.post("/register")
def register(user: User):
    cursor.execute(
        "INSERT OR REPLACE INTO users VALUES (?, ?, ?)",
        (user.username, user.public_key, user.chat_id)
    )
    conn.commit()
    return {"status": "ok"}


@app.get("/user/{username}")
def get_user(username: str):
    cursor.execute(
        "SELECT public_key, chat_id FROM users WHERE username=?",
        (username,)
    )
    row = cursor.fetchone()
    if not row:
        return {"error": "not found"}

    return {
        "public_key": row[0],
        "chat_id": row[1]
    }


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)