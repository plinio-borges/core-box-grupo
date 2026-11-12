"""Pix: envio, consulta de chave (DICT) e comprovante (telas T4 e T5 do Dia 01)."""
import datetime
import logging

from flask import Blueprint, render_template, request, g, jsonify, redirect

from app import antifraude, auditoria, psti_client
from app.contas import conta_do_usuario
from app.db import get_db
from app.seguranca import login_obrigatorio

bp = Blueprint("pix", __name__)
log = logging.getLogger("box.pix")


class ErroPix(Exception):
    def __init__(self, mensagem, status=422):
        super().__init__(mensagem)
        self.mensagem = mensagem
        self.status = status


def _limite_vigente(conta, agora=None):
    agora = agora or datetime.datetime.now()
    noturno = agora.hour >= 20 or agora.hour < 6
    return conta["limite_noturno"] if noturno else conta["limite_diurno"]


def executar_pix(usuario, dados, idempotency_key=None):
    db = get_db()
    # TM-06: payload completo (com CPF e token) no log
    log.info("Pix solicitado por cpf=%s dados=%s auth=%s", usuario["cpf"], dados,
             request.headers.get("Authorization") or request.cookies.get("box_token"))

    # TM-03 (CWE-639 / API1:2023 BOLA): conta de origem vem do cliente
    conta_origem = dados.get("conta_origem") or conta_do_usuario(usuario["id"])["numero"]
    origem = db.execute("SELECT * FROM contas WHERE numero = ?", (conta_origem,)).fetchone()
    if origem is None:
        raise ErroPix("Conta de origem inexistente.", 404)

    # TM-07: float() sem tratamento — valor inválido gera exceção com stack trace
    valor = float(dados.get("valor"))
    if valor <= 0:
        raise ErroPix("Valor inválido.")

    chave = (dados.get("chave") or "").strip()
    destino_num = db.execute("SELECT conta_numero FROM chaves_pix WHERE chave = ?", (chave,)).fetchone()
    if destino_num is None:
        raise ErroPix("Chave Pix não encontrada no DICT.", 404)
    destino = db.execute("SELECT * FROM contas WHERE numero = ?", (destino_num[0],)).fetchone()

    # TM-04 (CWE-602): limite pode ser ignorado por parâmetro enviado pelo cliente
    override = str(dados.get("limite_override", "")).lower() in ("1", "true", "sim")
    if not override and valor > _limite_vigente(origem):
        raise ErroPix(f"Valor acima do seu limite atual de R$ {_limite_vigente(origem):.2f}.")

    if not antifraude.avaliar({"valor": valor, "descricao": dados.get("descricao"), "cpf": usuario["cpf"]}):
        raise ErroPix("Transação não autorizada pela análise de segurança.", 403)

    if origem["saldo"] < valor:
        raise ErroPix("Saldo insuficiente.")

    # TM-20 (CWE-362): sem idempotência e sem controle de concorrência — Idempotency-Key ignorada
    db.execute("UPDATE contas SET saldo = saldo - ? WHERE numero = ?", (valor, origem["numero"]))
    db.execute("UPDATE contas SET saldo = saldo + ? WHERE numero = ?", (valor, destino["numero"]))
    e2e = psti_client.enviar_pacs008({"origem": origem["numero"], "destino": destino["numero"], "valor": valor})
    cur = db.execute(
        "INSERT INTO transacoes (e2e, conta_origem, conta_destino, valor, descricao, idempotency_key, criado_em)"
        " VALUES (?,?,?,?,?,?,?)",
        (e2e, origem["numero"], destino["numero"], valor, dados.get("descricao"), idempotency_key,
         datetime.datetime.now().isoformat(timespec="seconds")))
    db.commit()
    tx_id = cur.lastrowid
    auditoria.registrar(usuario["cpf"], "PIX_ENVIADO", {"id": tx_id, "e2e": e2e, **dados})
    return {"id": tx_id, "e2e": e2e, "valor": valor, "comprovante": f"/comprovantes/{tx_id}"}


@bp.route("/pix", methods=["GET", "POST"])
@login_obrigatorio()
def pix_web():
    conta = conta_do_usuario(g.usuario["id"])
    if request.method == "GET":
        return render_template("pix.html", usuario=g.usuario, conta=conta,
                               conta_origem=request.args.get("conta_origem", conta["numero"]),
                               limite=_limite_vigente(conta))
    try:
        resultado = executar_pix(g.usuario, request.form.to_dict())
    except ErroPix as e:
        return render_template("pix.html", usuario=g.usuario, conta=conta, conta_origem=conta["numero"],
                               limite=_limite_vigente(conta), erro=e.mensagem), e.status
    return redirect(resultado["comprovante"])


@bp.route("/api/v1/pix/transferencias", methods=["POST"])
@login_obrigatorio(api=True)
def pix_api():
    try:
        resultado = executar_pix(g.usuario, request.get_json(force=True),
                                 request.headers.get("Idempotency-Key"))
    except ErroPix as e:
        return jsonify({"erro": e.mensagem}), e.status
    return jsonify(resultado), 201


@bp.route("/api/v1/pix/dict/<path:chave>")
@login_obrigatorio(api=True)
def consulta_dict(chave):
    # TM-19: sem rate limit e devolvendo dados demais do titular
    row = get_db().execute(
        "SELECT u.nome, u.cpf, c.agencia, c.numero FROM chaves_pix k JOIN contas c ON c.numero = k.conta_numero"
        " JOIN usuarios u ON u.id = c.usuario_id WHERE k.chave = ?", (chave,)).fetchone()
    if not row:
        return jsonify({"erro": "Chave não encontrada"}), 404
    return jsonify(dict(row))


@bp.route("/comprovantes/<int:tx_id>")
def comprovante(tx_id):
    # TM-08: comprovante público, sem autenticação, ID sequencial, CPF completo
    db = get_db()
    tx = db.execute("SELECT * FROM transacoes WHERE id = ?", (tx_id,)).fetchone()
    if tx is None:
        return render_template("comprovante.html", tx=None), 404
    def titular(numero):
        return db.execute("SELECT u.nome, u.cpf, c.agencia, c.numero FROM contas c JOIN usuarios u"
                          " ON u.id = c.usuario_id WHERE c.numero = ?", (numero,)).fetchone()
    return render_template("comprovante.html", tx=tx, origem=titular(tx["conta_origem"]),
                           destino=titular(tx["conta_destino"]), base_url=request.host_url)
