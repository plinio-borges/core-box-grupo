"""Pix: envio, consulta de chave (DICT) e comprovante (telas T4 e T5 do Dia 01)."""
import datetime
import logging
import math
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
    log.info("Pix solicitado por usuario_id=%s", usuario["id"])

    # Correcao TM-03 (BOLA): conta de origem sempre derivada do usuario autenticado (sem ler do payload)
    conta_usuario = conta_do_usuario(usuario["id"])
    if "conta_origem" in dados and str(dados["conta_origem"]).strip() != str(conta_usuario["numero"]):
        auditoria.registrar(usuario["cpf"], "BOLA_ATTEMPT", {"conta_tentada": str(dados["conta_origem"])})
        raise ErroPix("Acesso negado: conta de origem não pertence ao titular autenticado.", 403)

    origem = db.execute("SELECT * FROM contas WHERE numero = ?", (conta_usuario["numero"],)).fetchone()
    if origem is None:
        raise ErroPix("Conta de origem inexistente.", 404)

    # Correcao TM-07: tratamento seguro de valor numerico sem vazar stack trace ou aceitar NaN
    try:
        valor = float(dados.get("valor"))
    except (TypeError, ValueError):
        raise ErroPix("Valor inválido.", 422)

    if math.isnan(valor) or math.isinf(valor) or valor <= 0:
        raise ErroPix("Valor inválido.", 422)

    # Correcao TM-20: validacao de idempotencia antes de debitar saldo
    if idempotency_key:
        tx_existente = db.execute(
            "SELECT id, e2e, valor FROM transacoes WHERE idempotency_key = ? AND conta_origem = ?",
            (idempotency_key, origem["numero"])
        ).fetchone()
        if tx_existente is not None:
            return {
                "id": tx_existente["id"],
                "e2e": tx_existente["e2e"],
                "valor": tx_existente["valor"],
                "comprovante": f"/comprovantes/{tx_existente['id']}",
            }

    chave = (dados.get("chave") or "").strip()
    destino_num = db.execute("SELECT conta_numero FROM chaves_pix WHERE chave = ?", (chave,)).fetchone()
    if destino_num is None:
        raise ErroPix("Chave Pix não encontrada no DICT.", 404)
    destino = db.execute("SELECT * FROM contas WHERE numero = ?", (destino_num[0],)).fetchone()

    # Correcao TM-04: limite validado estritamente no servidor (ignora flag limite_override)
    if "limite_override" in dados:
        auditoria.registrar(usuario["cpf"], "LIMIT_OVERRIDE_ATTEMPT", {"valor": valor})

    if valor > _limite_vigente(origem):
        raise ErroPix(f"Valor acima do seu limite atual de R$ {_limite_vigente(origem):.2f}.", 422)

    if not antifraude.avaliar({"valor": valor, "descricao": dados.get("descricao"), "cpf": usuario["cpf"]}):
        raise ErroPix("Transação não autorizada pela análise de segurança.", 403)

    if origem["saldo"] < valor:
        raise ErroPix("Saldo insuficiente.", 422)

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
    auditoria.registrar(usuario["cpf"], "PIX_ENVIADO", {"id": tx_id, "e2e": e2e, "valor": valor})
    return {"id": tx_id, "e2e": e2e, "valor": valor, "comprovante": f"/comprovantes/{tx_id}"}


@bp.route("/pix", methods=["GET", "POST"])
@login_obrigatorio()
def pix_web():
    conta = conta_do_usuario(g.usuario["id"])
    if request.method == "GET":
        return render_template("pix.html", usuario=g.usuario, conta=conta,
                               conta_origem=conta["numero"],
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
    dados = request.get_json(silent=True) or {}
    try:
        resultado = executar_pix(g.usuario, dados, request.headers.get("Idempotency-Key"))
    except ErroPix as e:
        return jsonify({"erro": e.mensagem}), e.status
    return jsonify(resultado), 201


@bp.route("/api/v1/pix/dict/<path:chave>")
@login_obrigatorio(api=True)
def consulta_dict(chave):
    row = get_db().execute(
        "SELECT u.nome, u.cpf, c.agencia, c.numero FROM chaves_pix k JOIN contas c ON c.numero = k.conta_numero"
        " JOIN usuarios u ON u.id = c.usuario_id WHERE k.chave = ?", (chave,)).fetchone()
    if not row:
        return jsonify({"erro": "Chave não encontrada"}), 404
    return jsonify(dict(row))


@bp.route("/comprovantes/<int:tx_id>")
@login_obrigatorio()
def comprovante(tx_id):
    # Correcao TM-08: exige autenticacao e valida se o usuario e parte da transacao
    db = get_db()
    tx = db.execute("SELECT * FROM transacoes WHERE id = ?", (tx_id,)).fetchone()
    if tx is None:
        return render_template("comprovante.html", tx=None), 404

    conta_usuario = conta_do_usuario(g.usuario["id"])
    origem_num = tx["conta_origem"]  # nosemgrep: box-tm03-conta-origem-vinda-do-cliente
    if conta_usuario["numero"] not in (origem_num, tx["conta_destino"]):
        return render_template("comprovante.html", tx=None), 403

    def titular(numero):
        return db.execute("SELECT u.nome, u.cpf, c.agencia, c.numero FROM contas c JOIN usuarios u"
                          " ON u.id = c.usuario_id WHERE c.numero = ?", (numero,)).fetchone()

    return render_template("comprovante.html", tx=tx, origem=titular(origem_num),
                           destino=titular(tx["conta_destino"]), base_url=request.host_url)
