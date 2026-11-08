"""
API de práctica: login -> genera token JWT -> endpoint protegido que lo valida.

Instalar:   pip install fastapi uvicorn pyjwt
Ejecutar:   uvicorn main:app --reload
Docs:       http://127.0.0.1:8000/docs
"""
import hashlib
import hmac
import os
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware




# --- Configuración -----------------------------------------------------------
SECRET_KEY = os.getenv("SECRET_KEY", "clave-de-practica-cambiala-por-una-mas-larga-123")
ALGORITHM = "HS256"
TOKEN_MINUTES = 15

# --- "Base de datos" de usuarios (solo para practicar) -----------------------
SALT = b"salt-de-practica"


def hashear_contrasena(password: str) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), SALT, 100_000)


USERS = {
    "ana": hashear_contrasena("1234"),
    "luis": hashear_contrasena("abcd"),
    "admin": hashear_contrasena("admin")
}

# --- App ---------------------------------------------------------------------
app = FastAPI(title="Practica JWT")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8080"],
    allow_methods=["*"],
    allow_headers=["*"],
)
bearer = HTTPBearer()


class LoginRequest(BaseModel):
    username: str
    password: str


def crear_token(username: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "iat": now,
        "exp": now + timedelta(minutes=TOKEN_MINUTES),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def obtener_usuario_actual(
    creds: HTTPAuthorizationCredentials = Depends(bearer),
) -> str:
    """Valida el token del header Authorization: Bearer <token>."""
    try:
        payload = jwt.decode(creds.credentials, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token expirado")
    except jwt.InvalidTokenError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token inválido")
    return payload["sub"]


@app.post("/login")
def iniciar_sesion(data: LoginRequest):
    """Valida credenciales y devuelve un token."""
    stored = USERS.get(data.username)
    if stored is None or not hmac.compare_digest(stored, hashear_contrasena(data.password)):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Credenciales incorrectas")
    return {
        "access_token": crear_token(data.username),
        "token_type": "bearer",
        "expires_in": TOKEN_MINUTES * 60,
    }


@app.get("/perfil")
def perfil(user: str = Depends(obtener_usuario_actual)):
    """Endpoint protegido: solo responde si el token es válido."""
    return {"mensaje": f"Hola {user}, tu token es válido"}


@app.get("/health")
def estado():
    """Endpoint público."""
    return {"status": "ok"}