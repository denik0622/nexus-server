from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel, EmailStr
from typing import Dict, Any, Optional
import hashlib
import uuid
import json
import os

app = FastAPI(title="NEXUS Sync Server")

DB_FILE = "cloud_database.json"

def load_db() -> Dict[str, Any]:
    if os.path.exists(DB_FILE):
        try:
            with open(DB_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {"users": {}, "data": {}}

def save_db(db: Dict[str, Any]):
    temp_file = DB_FILE + ".tmp"
    with open(temp_file, "w", encoding="utf-8") as f:
        json.dump(db, f, ensure_ascii=False, indent=2)
    os.replace(temp_file, DB_FILE)

def hash_password(password: str, salt: str = None) -> tuple[str, str]:
    salt = salt or uuid.uuid4().hex
    digest = hashlib.sha256(f"{salt}:{password}".encode("utf-8")).hexdigest()
    return salt, digest

class AuthPayload(BaseModel):
    email: EmailStr
    password: str
    name: Optional[str] = ""

class SyncPayload(BaseModel):
    email: EmailStr
    password: str
    data: Dict[str, Any]

@app.post("/register")
def register(payload: AuthPayload):
    db = load_db()
    email = payload.email.strip().lower()
    if email in db["users"]:
        raise HTTPException(status_code=400, detail="Пользователь уже существует")
    
    salt, p_hash = hash_password(payload.password)
    db["users"][email] = {
        "salt": salt,
        "password_hash": p_hash,
        "name": payload.name.strip() if payload.name else ""
    }
    db["data"][email] = {"weeks": {}, "habits": {}, "pills": {}, "profile": {"name": payload.name}}
    save_db(db)
    return {"status": "success", "message": "Регистрация успешна"}

@app.post("/login")
def login(payload: AuthPayload):
    db = load_db()
    email = payload.email.strip().lower()
    user = db["users"].get(email)
    if not user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    
    _, candidate_hash = hash_password(payload.password, user["salt"])
    if candidate_hash != user["password_hash"]:
        raise HTTPException(status_code=401, detail="Неверный пароль")
    
    return {"status": "success", "user_data": db["data"].get(email, {})}

@app.post("/sync/get")
def get_cloud_data(payload: AuthPayload):
    db = load_db()
    email = payload.email.strip().lower()
    user = db["users"].get(email)
    if not user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    
    _, candidate_hash = hash_password(payload.password, user["salt"])
    if candidate_hash != user["password_hash"]:
        raise HTTPException(status_code=401, detail="Неверный пароль")
        
    return {"status": "success", "data": db["data"].get(email, {})}

@app.post("/sync/push")
def push_cloud_data(payload: SyncPayload):
    db = load_db()
    email = payload.email.strip().lower()
    user = db["users"].get(email)
    if not user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    
    _, candidate_hash = hash_password(payload.password, user["salt"])
    if candidate_hash != user["password_hash"]:
        raise HTTPException(status_code=401, detail="Неверный пароль")
        
    db["data"][email] = payload.data
    save_db(db)
    return {"status": "success", "message": "Данные синхронизированы"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

