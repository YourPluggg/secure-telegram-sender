from fastapi import FastAPI
from pydantic import BaseModel
import sqlite3
import uvicorn  # для запуска

app = FastAPI()

conn = sqlite3.connect("db.sqlite", check_same_thread=False)
cursor = conn.cursor()

#таблица - users
cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    public_key TEXT
)
""")

class User(BaseModel):
    username: str
    public_key: str

@app.post("/register")
def register(user: User):
    cursor.execute("INSERT OR REPLACE INTO users VALUES (?, ?)",
                   (user.username, user.public_key))
    conn.commit()
    return {"status": "ok"}

@app.get("/key/{username}")
def get_key(username: str):
    cursor.execute("SELECT public_key FROM users WHERE username=?", (username,))
    row = cursor.fetchone()
    return {"public_key": row[0] if row else None}


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)