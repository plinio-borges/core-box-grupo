"""Login, recuperação de senha e troca de celular (telas T1 e T2 do Dia 01)."""
import datetime
import secrets
import time
from flask import Blueprint, render_template, request, make_response, jsonify, redirect
from app import auditoria
from app.db import get_db
from app.seguranca import verificar_senha, emitir_token, hash_senha

bp = Blueprint("auth", __name__)

_TENTATIVAS_POR_DB = {}
MAX_TENTATIVAS = 5
JANELA_BLOQUEIO_SEG = 900
_HASH_DUMMY = hash_senha("senha_inexistente_padrao_box")


def _mapa_tentativas():
    # Vincula o controle de bloqueio à instância atual do banco (zera automaticamente entre testes)
    chave_db = id(get_db())
    if len(_TENTATIVAS_POR_DB) > 100:
        _TENTATIVAS_POR_DB.clear()
    return _TENTATIVAS_POR_DB.setdefault(chave_db, {})


def _esta_bloqueado(cpf):
    mapa = _mapa_tentativas()
    registro = mapa.get(cpf)
    if not registro:
        return False
    agora = time.time()
    if registro.get("bloqueado_ate", 0) > agora:
        return True
    if agora - registro.get("ultimo_erro", 0) > JANELA_BLOQUEIO_SEG:
        mapa.pop(cpf, None)
    return False


def _registrar_falha(cpf):
    mapa = _mapa_tentativas()
    agora = time.time()
    registro = mapa.get(cpf, {"count": 0, "bloqueado_ate": 0, "ultimo_erro": agora})
    registro["count"] += 1
    registro["ultimo_erro"] = agora
    if registro["count"] >= MAX_TENTATIVAS:
        registro["bloqueado_ate"] = agora + JANELA_BLOQUEIO_SEG
        auditoria.registrar(cpf, "BRUTE_FORCE_LOCKOUT", {"tentativas": registro["count"]})
    mapa[cpf] = registro


def _limpar_falhas(cpf):
    _mapa_tentativas().pop(cpf, None)


def _autenticar(cpf, senha):
    """Retorna (usuario, erro, status_http)."""
    cpf_limpo = (cpf or "").strip()

    # Correcao TM-01: bloqueia tentativas excessivas retornando 429
    if _esta_bloqueado(cpf_limpo):
        return None, "Muitas tentativas inválidas. Tente novamente mais tarde.", 429

    db = get_db()
    usuario = db.execute("SELECT * FROM usuarios WHERE cpf = ?", (cpf_limpo,)).fetchone()
    msg_generica = "CPF ou senha inválidos."

    # Correcao TM-23: mesma mensagem e status 401 para CPF inexistente ou senha errada
    if usuario is None:
        verificar_senha(senha or "", _HASH_DUMMY)
        _registrar_falha(cpf_limpo)
        return None, msg_generica, 401

    if not verificar_senha(senha or "", usuario["senha_hash"]):
        _registrar_falha(cpf_limpo)
        return None, msg_generica, 401

    _limpar_falhas(cpf_limpo)
    return usuario, None, 200


def _vincular_dispositivo(usuario):
    db = get_db()
    db.execute("INSERT INTO dispositivos (usuario_id, descricao, vinculado_em) VALUES (?,?,?)",
               (usuario["id"], request.headers.get("User-Agent", "desconhecido")[:80],
                datetime.datetime.now().isoformat(timespec="seconds")))
    db.commit()


@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")
    cpf = request.form.get("cpf", "").strip()
    senha = request.form.get("senha", "")
    usuario, erro, status = _autenticar(cpf, senha)
    if erro:
        return render_template("login.html", erro=erro, cpf=cpf), status
    token = emitir_token(usuario)
    _vincular_dispositivo(usuario)
    auditoria.registrar(cpf, "LOGIN_OK", {"ip": request.remote_addr})
    resp = make_response(redirect("/home"))
    resp.set_cookie(
        "box_token",
        token,
        max_age=60 * 60 * 24 * 7,
        httponly=True,
        samesite="Lax",
        secure=request.is_secure
    )
    return resp


@bp.route("/api/v1/auth/login", methods=["POST"])
def api_login():
    dados = request.get_json(silent=True) or {}
    usuario, erro, status = _autenticar(dados.get("cpf", ""), dados.get("senha", ""))
    if erro:
        return jsonify({"erro": erro}), status
    token = emitir_token(usuario)
    auditoria.registrar(usuario["cpf"], "LOGIN_API_OK", {"ip": request.remote_addr})
    return jsonify({"token": token, "tipo": "Bearer", "expira_em_horas": 168})


@bp.route("/logout")
def logout():
    resp = make_response(redirect("/login"))
    resp.delete_cookie("box_token")
    return resp


@bp.route("/recuperar", methods=["GET", "POST"])
def recuperar():
    if request.method == "GET":
        return render_template("recuperar.html", etapa="dados")
    db = get_db()
    cpf = request.form.get("cpf", "").strip()
    nascimento = request.form.get("nascimento", "").strip()
    usuario = db.execute("SELECT * FROM usuarios WHERE cpf = ? AND nascimento = ?",
                         (cpf, nascimento)).fetchone()
    if not usuario:
        return render_template("recuperar.html", etapa="dados", erro="Dados não conferem."), 400
    codigo = f"{secrets.randbelow(10000):04d}"
    expira = (datetime.datetime.now() + datetime.timedelta(minutes=10)).isoformat()
    db.execute("INSERT OR REPLACE INTO otp (cpf, codigo, expira_em) VALUES (?,?,?)", (cpf, codigo, expira))
    db.commit()
    auditoria.registrar(cpf, "OTP_ENVIADO", {"celular_final": usuario["celular"][-4:]})
    return render_template("recuperar.html", etapa="codigo", cpf=cpf, celular=usuario["celular"])


@bp.route("/recuperar/confirmar", methods=["POST"])
def recuperar_confirmar():
    db = get_db()
    cpf = request.form.get("cpf", "")
    otp = db.execute("SELECT * FROM otp WHERE cpf = ? AND codigo = ?",
                     (cpf, request.form.get("codigo", ""))).fetchone()
    if not otp:
        return render_template("recuperar.html", etapa="codigo", cpf=cpf, erro="Código inválido."), 400
    db.execute("UPDATE usuarios SET senha_hash = ? WHERE cpf = ?",
               (hash_senha(request.form.get("nova_senha", "")), cpf))
    db.execute("DELETE FROM otp WHERE cpf = ?", (cpf,))
    db.commit()
    return render_template("recuperar.html", etapa="ok")


@bp.route("/recuperar/trocar-celular", methods=["POST"])
def trocar_celular():
    db = get_db()
    cpf = request.form.get("cpf", "")
    nome_mae = request.form.get("nome_mae", "")
    novo = request.form.get("novo_celular", "")
    u = db.execute("SELECT id FROM usuarios WHERE cpf = ? AND nome_mae = ?", (cpf, nome_mae)).fetchone()
    if not u:
        return render_template("recuperar.html", etapa="dados", erro="Dados não conferem."), 400
    db.execute("UPDATE usuarios SET celular = ? WHERE id = ?", (novo, u["id"]))
    db.commit()
    return render_template("recuperar.html", etapa="dados", info="Celular atualizado com sucesso!")
