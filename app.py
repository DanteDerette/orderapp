from __future__ import annotations

import os
import secrets
import uuid
import sqlite3
import logging
import base64
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, abort, g

from crypto import derive_kek, generate_dek, wrap_dek, unwrap_dek, encrypt_field, decrypt_field


# ── Secret Key ──────────────────────────────────────────────────────
def _load_or_create_secret_key() -> str:
    env = os.getenv("SECRET_KEY")
    if env:
        return env
    key_file = os.path.join(os.path.dirname(__file__), ".secret_key")
    if os.path.exists(key_file):
        return open(key_file).read().strip()
    key = secrets.token_hex(32)
    with open(key_file, "w") as f:
        f.write(key)
    return key


app = Flask(__name__)
app.secret_key = _load_or_create_secret_key()
app.config["DEBUG"] = os.getenv("FLASK_DEBUG", "0") == "1"

DB_PATH = os.path.join(os.path.dirname(__file__), "orderapp.db")

# DEK vive apenas em memória: {token_uuid: dek_bytes}
# Se o servidor reiniciar, usuários precisam fazer login novamente.
_dek_store: dict[str, bytes] = {}

logging.basicConfig(level=logging.INFO)


# ── DB ──────────────────────────────────────────────────────────────

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)

    db.execute("""
        CREATE TABLE IF NOT EXISTS usuarios (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            login       TEXT UNIQUE NOT NULL,
            nome        TEXT NOT NULL,
            senha_hash  TEXT NOT NULL,
            kek_salt    TEXT NOT NULL,
            dek_wrapped TEXT NOT NULL
        )
    """)

    # Campos sensíveis são armazenados cifrados; criado_em fica em texto
    # para permitir ordenação sem precisar decifrar tudo.
    db.execute("""
        CREATE TABLE IF NOT EXISTS caixas (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            banco_enc      TEXT NOT NULL DEFAULT '',
            data_enc       TEXT,
            valor_enc      TEXT NOT NULL DEFAULT '',
            criado_por_enc TEXT,
            criado_em      TEXT DEFAULT (datetime('now'))
        )
    """)

    db.execute("""
        CREATE TABLE IF NOT EXISTS faturas (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            cartao_enc      TEXT NOT NULL DEFAULT '',
            vencimento_enc  TEXT,
            valor_enc       TEXT NOT NULL DEFAULT '',
            pago_enc        TEXT NOT NULL DEFAULT '',
            criado_por_enc  TEXT,
            criado_em       TEXT DEFAULT (datetime('now'))
        )
    """)

    if db.execute("SELECT COUNT(*) FROM usuarios").fetchone()[0] == 0:
        _seed_users(db)

    db.commit()
    db.close()


def _seed_users(db):
    from werkzeug.security import generate_password_hash

    dek = generate_dek()

    usuarios_iniciais = [
        ("dantederette", "dante1946dante1946dante1946", "Dante Derette"),
        ("admin",        "admin123",                   "Administrador"),
    ]

    for login, senha, nome in usuarios_iniciais:
        kek_salt    = os.urandom(32)
        kek         = derive_kek(senha, kek_salt)
        dek_wrapped = wrap_dek(dek, kek)
        senha_hash  = generate_password_hash(senha)
        salt_b64    = base64.urlsafe_b64encode(kek_salt).decode("ascii")
        db.execute(
            "INSERT INTO usuarios (login, nome, senha_hash, kek_salt, dek_wrapped) VALUES (?,?,?,?,?)",
            (login, nome, senha_hash, salt_b64, dek_wrapped),
        )


# ── Auth ─────────────────────────────────────────────────────────────

def get_dek() -> bytes | None:
    token = session.get("_dek_token")
    return _dek_store.get(token) if token else None


def login_necessario(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("usuario_id") or get_dek() is None:
            session.clear()
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def sanitize(val, max_len=200):
    if val is None:
        return ""
    return str(val).strip()[:max_len]


# ── Login ────────────────────────────────────────────────────────────

@app.route("/login", methods=["GET", "POST"])
def login():
    erro = None
    if request.method == "POST":
        from werkzeug.security import check_password_hash

        login_val = sanitize(request.form.get("login"), 100)
        senha_val = request.form.get("senha", "")

        db  = get_db()
        row = db.execute("SELECT * FROM usuarios WHERE login = ?", (login_val,)).fetchone()

        if row and check_password_hash(row["senha_hash"], senha_val):
            try:
                kek_salt = base64.urlsafe_b64decode(row["kek_salt"])
                kek      = derive_kek(senha_val, kek_salt)
                dek      = unwrap_dek(row["dek_wrapped"], kek)

                token = str(uuid.uuid4())
                _dek_store[token] = dek

                session["usuario_id"]   = row["id"]
                session["usuario_nome"] = row["nome"]
                session["_dek_token"]   = token
                return redirect(url_for("caixas"))
            except Exception:
                pass  # senha correta mas DEK corrompida — trata como falha

        erro = "Login ou senha inválidos."
    return render_template("login.html", erro=erro)


@app.route("/logout", methods=["POST"])
def logout():
    token = session.get("_dek_token")
    if token:
        _dek_store.pop(token, None)   # apaga DEK da memória imediatamente
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
def index():
    return redirect(url_for("caixas"))


# ── Helpers de criptografia ──────────────────────────────────────────

def _decrypt_row(row, dek: bytes) -> dict:
    """Decifra uma linha do banco em dicionário com tipos corretos."""
    def safe(val):
        if not val:
            return ""
        try:
            return decrypt_field(val, dek)
        except Exception:
            return ""

    data_str = safe(row["data_enc"])
    data_obj = None
    if data_str:
        try:
            data_obj = datetime.strptime(data_str, "%Y-%m-%d")
        except ValueError:
            pass

    valor_str = safe(row["valor_enc"])
    try:
        valor_f = float(valor_str) if valor_str else 0.0
    except ValueError:
        valor_f = 0.0

    return {
        "id":         row["id"],
        "banco":      safe(row["banco_enc"]),
        "data":       data_obj,
        "valor":      valor_f,
        "criado_por": safe(row["criado_por_enc"]),
        "criado_em":  row["criado_em"],
    }


# ── Caixas ───────────────────────────────────────────────────────────

@app.route("/caixas")
@login_necessario
def caixas():
    mes   = sanitize(request.args.get("mes"),   4)
    ano   = sanitize(request.args.get("ano"),   4)
    banco = sanitize(request.args.get("banco"), 150)

    dek  = get_dek()
    db   = get_db()
    rows = db.execute("SELECT * FROM caixas ORDER BY criado_em DESC").fetchall()

    # Decifra tudo em memória; filtra em Python (dados são criptografados no banco)
    todos = [_decrypt_row(r, dek) for r in rows]

    filtrados = []
    for c in todos:
        if mes   and (not c["data"] or c["data"].strftime("%m") != mes.zfill(2)):
            continue
        if ano   and (not c["data"] or c["data"].strftime("%Y") != ano):
            continue
        if banco and c["banco"] != banco:
            continue
        filtrados.append(c)

    filtrados.sort(key=lambda c: c["data"] or datetime.min, reverse=True)

    total  = sum(c["valor"] for c in filtrados)
    bancos = sorted({c["banco"] for c in todos if c["banco"]})

    caixas_list = [type("Obj", (), c)() for c in filtrados]
    return render_template(
        "caixas.html",
        caixas=caixas_list,
        total=total,
        filtros={"mes": mes, "ano": ano, "banco": banco},
        bancos=bancos,
    )


@app.route("/caixas/novo", methods=["GET"])
@login_necessario
def caixas_novo_form():
    hoje = datetime.now().strftime("%Y-%m-%d")
    return render_template("caixas_form.html", caixa=None, hoje=hoje, erro=None, form=None)


@app.route("/caixas/novo", methods=["POST"])
@login_necessario
def caixas_novo():
    dek    = get_dek()
    banco  = sanitize(request.form.get("banco"), 150)
    data   = sanitize(request.form.get("data"),  10)
    try:
        valor = round(float(request.form.get("valor") or 0), 2)
    except ValueError:
        valor = 0.0
    usuario = session.get("usuario_nome", "")

    db  = get_db()
    cur = db.execute(
        "INSERT INTO caixas (banco_enc, data_enc, valor_enc, criado_por_enc) VALUES (?,?,?,?)",
        (
            encrypt_field(banco,          dek),
            encrypt_field(data,           dek) if data else None,
            encrypt_field(str(valor),     dek),
            encrypt_field(usuario,        dek),
        ),
    )
    db.commit()
    return redirect(url_for("caixas_editar_form", caixa_id=cur.lastrowid))


@app.route("/caixas/<int:caixa_id>/editar", methods=["GET"])
@login_necessario
def caixas_editar_form(caixa_id):
    dek = get_dek()
    db  = get_db()
    row = db.execute("SELECT * FROM caixas WHERE id = ?", (caixa_id,)).fetchone()
    if not row:
        abort(404)
    caixa_obj = type("Obj", (), _decrypt_row(row, dek))()
    hoje = datetime.now().strftime("%Y-%m-%d")
    return render_template("caixas_form.html", caixa=caixa_obj, hoje=hoje, erro=None, form=None)


@app.route("/caixas/<int:caixa_id>/editar", methods=["POST"])
@login_necessario
def caixas_editar(caixa_id):
    dek   = get_dek()
    banco = sanitize(request.form.get("banco"), 150)
    data  = sanitize(request.form.get("data"),  10)
    try:
        valor = round(float(request.form.get("valor") or 0), 2)
    except ValueError:
        valor = 0.0

    db = get_db()
    db.execute(
        "UPDATE caixas SET banco_enc=?, data_enc=?, valor_enc=? WHERE id=?",
        (
            encrypt_field(banco,      dek),
            encrypt_field(data,       dek) if data else None,
            encrypt_field(str(valor), dek),
            caixa_id,
        ),
    )
    db.commit()
    return redirect(url_for("caixas_editar_form", caixa_id=caixa_id))


@app.route("/caixas/<int:caixa_id>/excluir", methods=["POST"])
@login_necessario
def caixas_excluir(caixa_id):
    db = get_db()
    db.execute("DELETE FROM caixas WHERE id = ?", (caixa_id,))
    db.commit()
    return redirect(url_for("caixas"))


# ── Faturas ──────────────────────────────────────────────────────────

def _decrypt_fatura(row, dek: bytes) -> dict:
    def safe(val):
        if not val:
            return ""
        try:
            return decrypt_field(val, dek)
        except Exception:
            return ""

    venc_str = safe(row["vencimento_enc"])
    venc_obj = None
    if venc_str:
        try:
            venc_obj = datetime.strptime(venc_str, "%Y-%m-%d")
        except ValueError:
            pass

    valor_str = safe(row["valor_enc"])
    try:
        valor_f = float(valor_str) if valor_str else 0.0
    except ValueError:
        valor_f = 0.0

    pago_str = safe(row["pago_enc"])
    pago = pago_str == "1"

    return {
        "id":         row["id"],
        "cartao":     safe(row["cartao_enc"]),
        "vencimento": venc_obj,
        "valor":      valor_f,
        "pago":       pago,
        "criado_por": safe(row["criado_por_enc"]),
        "criado_em":  row["criado_em"],
    }


@app.route("/faturas")
@login_necessario
def faturas():
    mes    = sanitize(request.args.get("mes"),    4)
    ano    = sanitize(request.args.get("ano"),    4)
    cartao = sanitize(request.args.get("cartao"), 150)
    pago   = sanitize(request.args.get("pago"),   1)

    dek  = get_dek()
    db   = get_db()
    rows = db.execute("SELECT * FROM faturas ORDER BY criado_em DESC").fetchall()

    todos = [_decrypt_fatura(r, dek) for r in rows]

    filtrados = []
    for f in todos:
        if mes    and (not f["vencimento"] or f["vencimento"].strftime("%m") != mes.zfill(2)):
            continue
        if ano    and (not f["vencimento"] or f["vencimento"].strftime("%Y") != ano):
            continue
        if cartao and f["cartao"] != cartao:
            continue
        if pago == "1" and not f["pago"]:
            continue
        if pago == "0" and f["pago"]:
            continue
        filtrados.append(f)

    filtrados.sort(key=lambda f: f["vencimento"] or datetime.min, reverse=True)

    total_geral  = sum(f["valor"] for f in filtrados)
    total_pago   = sum(f["valor"] for f in filtrados if f["pago"])
    total_aberto = sum(f["valor"] for f in filtrados if not f["pago"])
    cartoes      = sorted({f["cartao"] for f in todos if f["cartao"]})

    faturas_list = [type("Obj", (), f)() for f in filtrados]
    return render_template(
        "faturas.html",
        faturas=faturas_list,
        total_geral=total_geral,
        total_pago=total_pago,
        total_aberto=total_aberto,
        filtros={"mes": mes, "ano": ano, "cartao": cartao, "pago": pago},
        cartoes=cartoes,
    )


@app.route("/faturas/novo", methods=["GET"])
@login_necessario
def faturas_novo_form():
    hoje = datetime.now().strftime("%Y-%m-%d")
    return render_template("faturas_form.html", fatura=None, hoje=hoje, erro=None, form=None)


@app.route("/faturas/novo", methods=["POST"])
@login_necessario
def faturas_novo():
    dek      = get_dek()
    cartao   = sanitize(request.form.get("cartao"), 150)
    venc     = sanitize(request.form.get("vencimento"), 10)
    pago     = "1" if request.form.get("pago") else "0"
    usuario  = session.get("usuario_nome", "")
    try:
        valor = round(float(request.form.get("valor") or 0), 2)
    except ValueError:
        valor = 0.0

    db  = get_db()
    cur = db.execute(
        "INSERT INTO faturas (cartao_enc, vencimento_enc, valor_enc, pago_enc, criado_por_enc) VALUES (?,?,?,?,?)",
        (
            encrypt_field(cartao,       dek),
            encrypt_field(venc,         dek) if venc else None,
            encrypt_field(str(valor),   dek),
            encrypt_field(pago,         dek),
            encrypt_field(usuario,      dek),
        ),
    )
    db.commit()
    return redirect(url_for("faturas_editar_form", fatura_id=cur.lastrowid))


@app.route("/faturas/<int:fatura_id>/editar", methods=["GET"])
@login_necessario
def faturas_editar_form(fatura_id):
    dek = get_dek()
    db  = get_db()
    row = db.execute("SELECT * FROM faturas WHERE id = ?", (fatura_id,)).fetchone()
    if not row:
        abort(404)
    fatura_obj = type("Obj", (), _decrypt_fatura(row, dek))()
    hoje = datetime.now().strftime("%Y-%m-%d")
    return render_template("faturas_form.html", fatura=fatura_obj, hoje=hoje, erro=None, form=None)


@app.route("/faturas/<int:fatura_id>/editar", methods=["POST"])
@login_necessario
def faturas_editar(fatura_id):
    dek    = get_dek()
    cartao = sanitize(request.form.get("cartao"), 150)
    venc   = sanitize(request.form.get("vencimento"), 10)
    pago   = "1" if request.form.get("pago") else "0"
    try:
        valor = round(float(request.form.get("valor") or 0), 2)
    except ValueError:
        valor = 0.0

    db = get_db()
    db.execute(
        "UPDATE faturas SET cartao_enc=?, vencimento_enc=?, valor_enc=?, pago_enc=? WHERE id=?",
        (
            encrypt_field(cartao,     dek),
            encrypt_field(venc,       dek) if venc else None,
            encrypt_field(str(valor), dek),
            encrypt_field(pago,       dek),
            fatura_id,
        ),
    )
    db.commit()
    return redirect(url_for("faturas_editar_form", fatura_id=fatura_id))


@app.route("/faturas/<int:fatura_id>/excluir", methods=["POST"])
@login_necessario
def faturas_excluir(fatura_id):
    db = get_db()
    db.execute("DELETE FROM faturas WHERE id = ?", (fatura_id,))
    db.commit()
    return redirect(url_for("faturas"))


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
