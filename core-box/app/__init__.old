"""Core Box — Core Bancário do Banco Box (versão de laboratório).

ATENÇÃO: esta aplicação contém vulnerabilidades INTENCIONAIS para fins de
treinamento (Projeto Integrador DevSecOps — Dia 02). Não use em produção.
"""
import logging
import traceback

from flask import Flask, redirect, request, make_response

from app import config, db


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.from_object(config.Config)
    if test_config:
        app.config.update(test_config)

    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    db.init_app(app)

    from app.auth import bp as auth_bp
    from app.contas import bp as contas_bp
    from app.pix import bp as pix_bp
    from app.backoffice import bp as backoffice_bp
    from app.onboarding import bp as onboarding_bp
    from app.api_interna import bp as interna_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(contas_bp)
    app.register_blueprint(pix_bp)
    app.register_blueprint(backoffice_bp)
    app.register_blueprint(onboarding_bp)
    app.register_blueprint(interna_bp)

    @app.route("/")
    def index():
        return redirect("/login")

    @app.route("/health")
    def health():
        # TM-07: expõe versão e ambiente para "facilitar o suporte"
        return {"status": "ok", "app": "core-box", "versao": config.Config.VERSAO,
                "ambiente": config.Config.AMBIENTE, "debug": app.config["DEBUG"]}

    @app.errorhandler(Exception)
    def erro_generico(exc):
        # TM-07 (CWE-209): devolve a stack trace completa ao cliente
        detalhe = traceback.format_exc()
        app.logger.error("Erro não tratado: %s", detalhe)
        resp = make_response(
            {"erro": str(exc), "tipo": exc.__class__.__name__, "trace": detalhe}, 500
        )
        return resp

    return app
