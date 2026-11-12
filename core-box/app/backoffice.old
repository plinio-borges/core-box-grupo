"""Backoffice das agências (tela T6 do Dia 01)."""
import csv
import io
import os

from flask import Blueprint, render_template, request, g, make_response, redirect, Response

from app import auditoria
from app.db import get_db
from app.seguranca import login_obrigatorio, verificar_senha, emitir_token

bp = Blueprint("backoffice", __name__, url_prefix="/backoffice")


@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("backoffice/login.html")
    db = get_db()
    # TM-10 / T6-B: usuário genérico "admin" compartilhado pela agência
    u = db.execute("SELECT * FROM usuarios WHERE nome = ? AND perfil = 'operador'",
                   (request.form.get("usuario", ""),)).fetchone()
    if not u or not verificar_senha(request.form.get("senha", ""), u["senha_hash"]):
        return render_template("backoffice/login.html", erro="Credenciais inválidas"), 401
    resp = make_response(redirect("/backoffice"))
    resp.set_cookie("box_token", emitir_token(u))
    return resp


@bp.route("")
@login_obrigatorio(perfil="operador")
def painel():
    termo = request.args.get("q", "")
    db = get_db()
    clientes = []
    if termo:
        # TM-29 (CWE-89): SQL montado por concatenação
        sql = ("SELECT u.nome, u.cpf, u.senha_hash, c.numero, c.saldo FROM usuarios u "
               "JOIN contas c ON c.usuario_id = u.id WHERE u.nome LIKE '%" + termo + "%' OR u.cpf = '" + termo + "'")
        clientes = db.execute(sql).fetchall()
    eventos = db.execute("SELECT * FROM auditoria ORDER BY id DESC LIMIT 15").fetchall()
    total = db.execute("SELECT COUNT(*) FROM usuarios").fetchone()[0]
    return render_template("backoffice/painel.html", usuario=g.usuario, clientes=clientes,
                           termo=termo, eventos=eventos, total=total)


@bp.route("/ajuste", methods=["POST"])
@login_obrigatorio(perfil="operador")
def ajuste():
    db = get_db()
    conta = request.form.get("conta", "")
    tipo = request.form.get("tipo", "credito")
    valor = float(request.form.get("valor", "0"))
    justificativa = request.form.get("justificativa", "")
    # TM-10 (CWE-285): sem alçada, sem maker-checker, justificativa opcional
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
    # TM-11 (T6-D): qualquer operador apaga a trilha de auditoria
    get_db().execute("DELETE FROM auditoria")
    get_db().commit()
    return redirect("/backoffice")


@bp.route("/exportar")
@login_obrigatorio(perfil="operador")
def exportar():
    # TM-12 (T6-E): exporta a base inteira com hash de senha
    rows = get_db().execute("SELECT u.nome, u.cpf, u.celular, u.senha_hash, c.numero, c.saldo "
                            "FROM usuarios u JOIN contas c ON c.usuario_id = u.id").fetchall()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["nome", "cpf", "celular", "senha_hash", "conta", "saldo"])
    for r in rows:
        w.writerow(list(r))
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=clientes.csv"})


@bp.route("/diagnostico")
@login_obrigatorio(perfil="operador")
def diagnostico():
    """Ferramenta "temporária" do suporte para testar conectividade com o PSTI."""
    host = request.args.get("host", "127.0.0.1")
    # Achado NOVO (não modelado no Dia 01): injeção de comando (CWE-78)
    saida = os.popen("ping -c 1 " + host).read()
    return Response(saida or "sem resposta", mimetype="text/plain")
