"""Funções de segurança do Core Box (autenticação, hash, JWT)."""
import datetime
import functools
import hashlib
import hmac
import jwt
from flask import current_app, g, request, jsonify, redirect
from werkzeug.security import generate_password_hash, check_password_hash
from app.db import get_db


def hash_senha(senha):
    # Correcao TM-12: PBKDF2-SHA256 com salt aleatório (substitui MD5 obsoleto)
    return generate_password_hash(senha, method="pbkdf2:sha256")


def verificar_senha(senha, senha_hash):
    if not senha_hash:
        return False
    if senha_hash.startswith(("pbkdf2:", "scrypt:")):
        return check_password_hash(senha_hash, senha)
    # Fallback de leitura para hashes legados do seed inicial do banco
    if len(senha_hash) == 32:
        legado = hashlib.md5(senha.encode()).hexdigest()  # nosemgrep: python.lang.security.insecure-hash-algorithms-md5.insecure-hash-algorithm-md5
        return hmac.compare_digest(legado, senha_hash)
    return False


def emitir_token(usuario):
    agora = datetime.datetime.now(datetime.timezone.utc)
    payload = {
        "sub": str(usuario["id"]),
        "cpf": usuario["cpf"],
        "nome": usuario["nome"],
        "perfil": usuario["perfil"],
        "iat": agora,
        "exp": agora + datetime.timedelta(hours=current_app.config["JWT_EXPIRACAO_HORAS"]),
    }
    token = jwt.encode(payload, current_app.config["JWT_SECRET"], algorithm="HS256")
    if isinstance(token, bytes):
        token = token.decode()
    return token


def _token_da_requisicao():
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:]
    return request.cookies.get("box_token")


def usuario_atual():
    token = _token_da_requisicao()
    if not token:
        return None
    try:
        dados = jwt.decode(token, current_app.config["JWT_SECRET"], algorithms=["HS256"])
    except jwt.PyJWTError:
        return None
    return get_db().execute("SELECT * FROM usuarios WHERE id = ?", (int(dados["sub"]),)).fetchone()


def login_obrigatorio(perfil=None, api=False):
    def deco(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            usuario = usuario_atual()
            if usuario is None or (perfil and usuario["perfil"] != perfil):
                if api or request.path.startswith("/api/"):
                    return jsonify({"erro": "não autenticado"}), 401
                destino = "/backoffice/login" if request.path.startswith("/backoffice") else "/login"
                return redirect(destino)
            g.usuario = usuario
            return fn(*args, **kwargs)
        return wrapper
    return deco
