"""Core Box — Core Bancário do Banco Box (versão endurecida)."""
import logging
from flask import Flask, redirect, make_response
from app import config, db


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.from_object(config.Config)
    if test_config:
        app.config.update(test_config)

    app.config["DEBUG"] = False
    app.config["PROPAGATE_EXCEPTIONS"] = False

    logging.basicConfig(
        level=logging.INFO,
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

    @app.after_request
    def adicionar_cabecalhos_seguranca(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        return response

    @app.route("/")
    def index():
        return redirect("/login")

    @app.route("/health")
    def health():
        return {"status": "ok"}

    @app.errorhandler(Exception)
    def erro_generico(exc):
        # Correcao TM-07: registra o erro internamente e devolve resposta generica sem stack trace
        app.logger.exception("Erro interno não tratado")
        resp = make_response({"erro": "Erro interno no servidor."}, 500)
        return resp

    return app
