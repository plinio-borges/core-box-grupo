"""Backoffice das agências (tela T6 do Dia 01)."""
import csv
import io
import math
import re
import socket
from flask import Blueprint, render_template, request, g, make_response, redirect, Response
from app import auditoria
from app.db import get_db
from app.seguranca import login_obrigatorio, verificar_senha, emitir_token

bp = Blueprint("backoffice", __name__, url_prefix="/backoffice")

LIMITE_ALCADA_OPERADOR = 10000.0
REGEX_HOST_SEGURO = re.compile(r"^[a-zA-Z0-9.-]{1,253}$")


@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("backoffice/login.html")
    db = get_db()
    u = db.execute("SELECT * FROM usuarios WHERE nome = ? AND perfil = 'operador'",
                   (request.form.get("usuario", ""),)).fetchone()
    if not u or not verificar_senha(request.form.get("senha", ""), u["senha_hash"]):
        return render_template("backoffice/login.html", erro="Credenciais inválidas"), 401
    resp = make_response(redirect("/backoffice"))
    resp.set_cookie(
        "box_token",
        emitir_token(u),
        httponly=True,
        samesite="Lax",
        secure=request.is_secure
    )
    return resp


@bp.route("")
@login_obrigatorio(perfil="operador")
def painel():
    termo = (request.args.get("q") or "").strip()
    db = get_db()
    clientes = []
    if termo:
        # Correcao TM-29: consulta SQL parametrizada (elimina SQL Injection)
        like_termo = f"%{termo}%"
        sql = (
            "SELECT u.nome, u.cpf, c.numero, c.saldo FROM usuarios u "
            "JOIN contas c ON c.usuario_id = u.id "
            "WHERE u.nome LIKE ? OR u.cpf = ?"
        )
        clientes = db.execute(sql, (like_termo, termo)).fetchall()
    eventos = db.execute("SELECT * FROM auditoria ORDER BY id DESC LIMIT 15").fetchall()
    total = db.execute("SELECT COUNT(*) FROM usuarios").fetchone()
    return render_template("backoffice/painel.html", usuario=g.usuario, clientes=clientes,
                           termo=termo, eventos=eventos, total=total)


@bp.route("/ajuste", methods=["POST"])
@login_obrigatorio(perfil="operador")
def ajuste():
    db = get_db()
    conta = (request.form.get("conta") or "").strip()
    tipo = request.form.get("tipo", "credito")
    justificativa = (request.form.get("justificativa") or "").strip()

    try:
        valor = float(request.form.get("valor", "0"))
    except (TypeError, ValueError):
        return {"erro": "Valor inválido."}, 400

    # Correcao TM-10 (Parte 1): recusa ajuste sem justificativa ou valor invalido com 400
    if math.isnan(valor) or math.isinf(valor) or valor <= 0 or not justificativa:
        erro_msg = "Justificativa obrigatória e valor deve ser maior que zero."
        if request.headers.get("Accept") == "application/json":
            return {"erro": erro_msg}, 400
        return Response(erro_msg, status=400, mimetype="text/plain")

    # Correcao TM-10 (Parte 2): acima de R$ 10.000 fica pendente de 2a aprovacao (202) sem alterar saldo
    if valor > LIMITE_ALCADA_OPERADOR:
        auditoria.registrar(g.usuario["nome"], "AJUSTE_PENDENTE_ALCADA",
                            {"conta": conta, "tipo": tipo, "valor": valor, "justificativa": justificativa})
        msg_pendente = "Ajuste acima de R$ 10.000,00 retido para 2ª aprovação (Maker-Checker)."
        if request.headers.get("Accept") == "application/json":
            return {"status": "pendente_aprovacao", "mensagem": msg_pendente, "conta": conta, "valor": valor}, 202
        return Response(msg_pendente, status=202, mimetype="text/plain")

    sinal = 1 if tipo == "credito" else -1
    db.execute("UPDATE contas SET saldo = saldo + ? WHERE numero = ?", (sinal * valor, conta))
    db.commit()
    auditoria.registrar(g.usuario["nome"], "AJUSTE_SALDO",
                        {"conta": conta, "tipo": tipo, "valor": valor, "justificativa": justificativa})
    if request.headers.get("Accept") == "application/json":
        return {"status": "efetivado", "conta": conta, "valor": valor}, 200
    return redirect("/backoffice?q=" + conta)


@bp.route("/auditoria/limpar", methods=["POST"])
@login_obrigatorio(perfil="operador")
def limpar_auditoria():
    return Response("Operação não permitida: trilha de auditoria é imutável.", status=403, mimetype="text/plain")


@bp.route("/exportar")
@login_obrigatorio(perfil="operador")
def exportar():
    rows = get_db().execute("SELECT u.nome, u.cpf, u.celular, c.numero, c.saldo "
                            "FROM usuarios u JOIN contas c ON c.usuario_id = u.id").fetchall()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["nome", "cpf", "celular", "conta", "saldo"])
    for r in rows:
        w.writerow(list(r))
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=clientes.csv"})


@bp.route("/diagnostico")
@login_obrigatorio(perfil="operador")
def diagnostico():
    """Ferramenta de suporte para testar conectividade TCP sem os.popen ou ping."""
    host = (request.args.get("host") or "127.0.0.1").strip()
    if not REGEX_HOST_SEGURO.match(host) or host.startswith("-"):
        return Response("Parâmetro host inválido.", status=400, mimetype="text/plain")
    try:
        with socket.create_connection((host, 443), timeout=3):
            saida = f"Conectividade TCP confirmada com {host}:443"
    except OSError:
        saida = f"Sem resposta TCP de {host}:443"
    return Response(saida, mimetype="text/plain")
