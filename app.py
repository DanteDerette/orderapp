from __future__ import annotations

import os
import hashlib
import sqlite3
import logging
import base64
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, abort, g
from cryptography.fernet import Fernet

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

logging.basicConfig(level=logging.INFO)


@app.template_filter("brl")
def brl_filter(value):
    try:
        s = "{:,.2f}".format(float(value))
        return s.replace(",", "X").replace(".", ",").replace("X", ".")
    except (ValueError, TypeError):
        return "0,00"


def _session_fernet() -> Fernet:
    raw = hashlib.sha256(app.secret_key.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(raw))


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

    db.execute("""
        CREATE TABLE IF NOT EXISTS contas_receber (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            descricao_enc   TEXT NOT NULL DEFAULT '',
            cliente_enc     TEXT NOT NULL DEFAULT '',
            vencimento_enc  TEXT,
            valor_enc       TEXT NOT NULL DEFAULT '',
            recebido_enc    TEXT NOT NULL DEFAULT '',
            criado_por_enc  TEXT,
            criado_em       TEXT DEFAULT (datetime('now'))
        )
    """)

    cols = {r[1] for r in db.execute("PRAGMA table_info(patrimonio)").fetchall()}
    if "ativo_enc" not in cols:
        db.execute("DROP TABLE IF EXISTS patrimonio")
    db.execute("""
        CREATE TABLE IF NOT EXISTS patrimonio (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            ativo_enc      TEXT NOT NULL DEFAULT '',
            passivo_enc    TEXT NOT NULL DEFAULT '',
            data_enc       TEXT,
            criado_por_enc TEXT,
            criado_em      TEXT DEFAULT (datetime('now'))
        )
    """)

    db.execute("""
        CREATE TABLE IF NOT EXISTS tarefas (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            texto_enc      TEXT NOT NULL DEFAULT '',
            feito_enc      TEXT NOT NULL DEFAULT '',
            criado_por_enc TEXT,
            criado_em      TEXT DEFAULT (datetime('now'))
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
    enc = session.get("_dek_enc")
    if not enc:
        return None
    try:
        return _session_fernet().decrypt(enc.encode())
    except Exception:
        return None


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

                session["usuario_id"]   = row["id"]
                session["usuario_nome"] = row["nome"]
                session["_dek_enc"]     = _session_fernet().encrypt(dek).decode()
                return redirect(url_for("caixas"))
            except Exception:
                pass  # senha correta mas DEK corrompida — trata como falha

        erro = "Login ou senha inválidos."
    return render_template("login.html", erro=erro)


@app.route("/logout", methods=["POST"])
def logout():
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

    bancos = sorted({c["banco"] for c in todos if c["banco"]})

    # Agrupa por data para exibir totalizador diário
    from itertools import groupby
    dias = []
    for data_key, grupo in groupby(filtrados, key=lambda c: c["data"]):
        itens = list(grupo)
        dias.append({
            "data":  data_key,
            "itens": [type("Obj", (), c)() for c in itens],
            "total": sum(c["valor"] for c in itens),
        })

    return render_template(
        "caixas.html",
        dias=dias,
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
    _snapshot_patrimonio(db, dek, "Caixa adicionado")
    db.commit()
    return redirect(url_for("caixas_ver", caixa_id=cur.lastrowid))


@app.route("/caixas/<int:caixa_id>")
@login_necessario
def caixas_ver(caixa_id):
    dek = get_dek()
    db  = get_db()
    row = db.execute("SELECT * FROM caixas WHERE id = ?", (caixa_id,)).fetchone()
    if not row:
        abort(404)
    caixa_obj = type("Obj", (), _decrypt_row(row, dek))()
    return render_template("caixas_form.html", caixa=caixa_obj)


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
    _snapshot_patrimonio(db, dek, "Caixa editado")
    db.commit()
    return redirect(url_for("caixas_ver", caixa_id=caixa_id))


@app.route("/caixas/<int:caixa_id>/excluir", methods=["POST"])
@login_necessario
def caixas_excluir(caixa_id):
    dek = get_dek()
    db  = get_db()
    db.execute("DELETE FROM caixas WHERE id = ?", (caixa_id,))
    _snapshot_patrimonio(db, dek, "Caixa excluído")
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

    cartoes = sorted({f["cartao"] for f in todos if f["cartao"]})

    from itertools import groupby
    dias = []
    for venc_key, grupo in groupby(filtrados, key=lambda f: f["vencimento"]):
        itens = list(grupo)
        dias.append({
            "vencimento": venc_key,
            "itens":      [type("Obj", (), f)() for f in itens],
            "total":      sum(f["valor"] for f in itens),
        })

    return render_template(
        "faturas.html",
        dias=dias,
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
    _snapshot_patrimonio(db, dek, "Fatura adicionada")
    db.commit()
    return redirect(url_for("faturas_ver", fatura_id=cur.lastrowid))


@app.route("/faturas/<int:fatura_id>")
@login_necessario
def faturas_ver(fatura_id):
    dek = get_dek()
    db  = get_db()
    row = db.execute("SELECT * FROM faturas WHERE id = ?", (fatura_id,)).fetchone()
    if not row:
        abort(404)
    fatura_obj = type("Obj", (), _decrypt_fatura(row, dek))()
    return render_template("faturas_form.html", fatura=fatura_obj)


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
    _snapshot_patrimonio(db, dek, "Fatura editada")
    db.commit()
    return redirect(url_for("faturas_ver", fatura_id=fatura_id))


@app.route("/faturas/<int:fatura_id>/excluir", methods=["POST"])
@login_necessario
def faturas_excluir(fatura_id):
    dek = get_dek()
    db  = get_db()
    db.execute("DELETE FROM faturas WHERE id = ?", (fatura_id,))
    _snapshot_patrimonio(db, dek, "Fatura excluída")
    db.commit()
    return redirect(url_for("faturas"))


# ── Contas a Receber ─────────────────────────────────────────────────

def _decrypt_conta(row, dek: bytes) -> dict:
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

    return {
        "id":         row["id"],
        "descricao":  safe(row["descricao_enc"]),
        "cliente":    safe(row["cliente_enc"]),
        "vencimento": venc_obj,
        "valor":      valor_f,
        "recebido":   safe(row["recebido_enc"]) == "1",
        "criado_por": safe(row["criado_por_enc"]),
        "criado_em":  row["criado_em"],
    }


@app.route("/contas-receber")
@login_necessario
def contas_receber():
    mes      = sanitize(request.args.get("mes"),      4)
    ano      = sanitize(request.args.get("ano"),      4)
    cliente  = sanitize(request.args.get("cliente"),  150)
    recebido = sanitize(request.args.get("recebido"), 1)

    dek  = get_dek()
    db   = get_db()
    rows = db.execute("SELECT * FROM contas_receber ORDER BY criado_em DESC").fetchall()

    todos = [_decrypt_conta(r, dek) for r in rows]

    filtrados = []
    for c in todos:
        if mes      and (not c["vencimento"] or c["vencimento"].strftime("%m") != mes.zfill(2)):
            continue
        if ano      and (not c["vencimento"] or c["vencimento"].strftime("%Y") != ano):
            continue
        if cliente  and c["cliente"] != cliente:
            continue
        if recebido == "1" and not c["recebido"]:
            continue
        if recebido == "0" and c["recebido"]:
            continue
        filtrados.append(c)

    filtrados.sort(key=lambda c: c["vencimento"] or datetime.min, reverse=True)

    clientes = sorted({c["cliente"] for c in todos if c["cliente"]})

    from itertools import groupby
    dias = []
    for venc_key, grupo in groupby(filtrados, key=lambda c: c["vencimento"]):
        itens = list(grupo)
        dias.append({
            "vencimento": venc_key,
            "itens":      [type("Obj", (), c)() for c in itens],
            "total":      sum(c["valor"] for c in itens),
        })

    return render_template(
        "contas_receber.html",
        dias=dias,
        filtros={"mes": mes, "ano": ano, "cliente": cliente, "recebido": recebido},
        clientes=clientes,
    )


@app.route("/contas-receber/novo", methods=["GET"])
@login_necessario
def contas_receber_novo_form():
    hoje = datetime.now().strftime("%Y-%m-%d")
    return render_template("contas_receber_form.html", conta=None, hoje=hoje, erro=None)


@app.route("/contas-receber/novo", methods=["POST"])
@login_necessario
def contas_receber_novo():
    dek       = get_dek()
    descricao = sanitize(request.form.get("descricao"), 200)
    cliente   = sanitize(request.form.get("cliente"),   150)
    venc      = sanitize(request.form.get("vencimento"), 10)
    recebido  = "1" if request.form.get("recebido") else "0"
    usuario   = session.get("usuario_nome", "")
    try:
        valor = round(float(request.form.get("valor") or 0), 2)
    except ValueError:
        valor = 0.0

    db  = get_db()
    cur = db.execute(
        "INSERT INTO contas_receber (descricao_enc, cliente_enc, vencimento_enc, valor_enc, recebido_enc, criado_por_enc) VALUES (?,?,?,?,?,?)",
        (
            encrypt_field(descricao,    dek),
            encrypt_field(cliente,      dek),
            encrypt_field(venc,         dek) if venc else None,
            encrypt_field(str(valor),   dek),
            encrypt_field(recebido,     dek),
            encrypt_field(usuario,      dek),
        ),
    )
    _snapshot_patrimonio(db, dek, "Conta a receber adicionada")
    db.commit()
    return redirect(url_for("contas_receber_ver", conta_id=cur.lastrowid))


@app.route("/contas-receber/<int:conta_id>")
@login_necessario
def contas_receber_ver(conta_id):
    dek = get_dek()
    db  = get_db()
    row = db.execute("SELECT * FROM contas_receber WHERE id = ?", (conta_id,)).fetchone()
    if not row:
        abort(404)
    conta_obj = type("Obj", (), _decrypt_conta(row, dek))()
    return render_template("contas_receber_form.html", conta=conta_obj)


@app.route("/contas-receber/<int:conta_id>/editar", methods=["POST"])
@login_necessario
def contas_receber_editar(conta_id):
    dek       = get_dek()
    descricao = sanitize(request.form.get("descricao"), 200)
    cliente   = sanitize(request.form.get("cliente"),   150)
    venc      = sanitize(request.form.get("vencimento"), 10)
    recebido  = "1" if request.form.get("recebido") else "0"
    try:
        valor = round(float(request.form.get("valor") or 0), 2)
    except ValueError:
        valor = 0.0
    db = get_db()
    db.execute(
        "UPDATE contas_receber SET descricao_enc=?, cliente_enc=?, vencimento_enc=?, valor_enc=?, recebido_enc=? WHERE id=?",
        (
            encrypt_field(descricao,  dek),
            encrypt_field(cliente,    dek),
            encrypt_field(venc,       dek) if venc else None,
            encrypt_field(str(valor), dek),
            encrypt_field(recebido,   dek),
            conta_id,
        ),
    )
    _snapshot_patrimonio(db, dek, "Conta a receber editada")
    db.commit()
    return redirect(url_for("contas_receber_ver", conta_id=conta_id))


@app.route("/contas-receber/<int:conta_id>/excluir", methods=["POST"])
@login_necessario
def contas_receber_excluir(conta_id):
    dek = get_dek()
    db  = get_db()
    db.execute("DELETE FROM contas_receber WHERE id = ?", (conta_id,))
    _snapshot_patrimonio(db, dek, "Conta a receber excluída")
    db.commit()
    return redirect(url_for("contas_receber"))


# ── Patrimônio Líquido ───────────────────────────────────────────────
# Snapshot automático gerado a cada mutação em caixas, faturas ou contas_receber.

def _decrypt_patrimonio(row, dek: bytes) -> dict:
    def safe(val):
        if not val:
            return ""
        try:
            return decrypt_field(val, dek)
        except Exception:
            return ""

    def to_float(v):
        try:
            return float(safe(v)) if v else 0.0
        except ValueError:
            return 0.0

    ativo   = to_float(row["ativo_enc"])
    passivo = to_float(row["passivo_enc"])

    return {
        "id":        row["id"],
        "ativo":     ativo,
        "passivo":   passivo,
        "pl":        ativo - passivo,
        "origem":    safe(row["criado_por_enc"]),
        "criado_em": row["criado_em"],
    }


def _snapshot_patrimonio(db, dek: bytes, origem: str):
    caixa_rows  = db.execute("SELECT * FROM caixas").fetchall()
    total_ativo = sum(_decrypt_row(r, dek)["valor"] for r in caixa_rows)

    conta_rows = db.execute("SELECT * FROM contas_receber").fetchall()
    for r in conta_rows:
        c = _decrypt_conta(r, dek)
        if not c["recebido"]:
            total_ativo += c["valor"]

    fatura_rows  = db.execute("SELECT * FROM faturas").fetchall()
    total_passivo = 0.0
    for r in fatura_rows:
        f = _decrypt_fatura(r, dek)
        if not f["pago"]:
            total_passivo += f["valor"]

    hoje = datetime.now().strftime("%Y-%m-%d")
    db.execute(
        "INSERT INTO patrimonio (ativo_enc, passivo_enc, data_enc, criado_por_enc) VALUES (?,?,?,?)",
        (
            encrypt_field(str(round(total_ativo,   2)), dek),
            encrypt_field(str(round(total_passivo, 2)), dek),
            encrypt_field(hoje,   dek),
            encrypt_field(origem, dek),
        ),
    )


@app.route("/patrimonio")
@login_necessario
def patrimonio():
    dek  = get_dek()
    db   = get_db()
    rows = db.execute("SELECT * FROM patrimonio ORDER BY criado_em DESC").fetchall()
    registros = [type("Obj", (), _decrypt_patrimonio(r, dek))() for r in rows]
    return render_template("patrimonio.html", registros=registros)


@app.route("/patrimonio/reconstruir", methods=["POST"])
@login_necessario
def patrimonio_reconstruir():
    dek = get_dek()
    db  = get_db()

    # Coleta todos os eventos das três tabelas com seus timestamps originais
    eventos = []
    for r in db.execute("SELECT * FROM caixas ORDER BY criado_em").fetchall():
        d = _decrypt_row(r, dek)
        d["tabela"] = "caixas"
        eventos.append(d)
    for r in db.execute("SELECT * FROM faturas ORDER BY criado_em").fetchall():
        d = _decrypt_fatura(r, dek)
        d["tabela"] = "faturas"
        eventos.append(d)
    for r in db.execute("SELECT * FROM contas_receber ORDER BY criado_em").fetchall():
        d = _decrypt_conta(r, dek)
        d["tabela"] = "contas_receber"
        eventos.append(d)

    # Ordena todos os eventos cronologicamente
    eventos.sort(key=lambda e: e["criado_em"])

    # Limpa histórico atual e reconstrói desde o início
    db.execute("DELETE FROM patrimonio")

    acc_caixas  = []
    acc_faturas = []
    acc_contas  = []

    origens = {
        "caixas":         "Caixa (retroativo)",
        "faturas":        "Fatura (retroativa)",
        "contas_receber": "Conta a receber (retroativa)",
    }

    for ev in eventos:
        tabela = ev["tabela"]
        if tabela == "caixas":
            acc_caixas.append(ev)
        elif tabela == "faturas":
            acc_faturas.append(ev)
        else:
            acc_contas.append(ev)

        total_ativo   = sum(c["valor"] for c in acc_caixas)
        total_ativo  += sum(c["valor"] for c in acc_contas if not c["recebido"])
        total_passivo = sum(f["valor"] for f in acc_faturas if not f["pago"])

        db.execute(
            "INSERT INTO patrimonio (ativo_enc, passivo_enc, data_enc, criado_por_enc, criado_em) VALUES (?,?,?,?,?)",
            (
                encrypt_field(str(round(total_ativo,   2)), dek),
                encrypt_field(str(round(total_passivo, 2)), dek),
                encrypt_field(ev["criado_em"][:10],         dek),
                encrypt_field(origens[tabela],              dek),
                ev["criado_em"],  # preserva o timestamp original
            ),
        )

    db.commit()
    return redirect(url_for("patrimonio"))


@app.route("/patrimonio/<int:item_id>/excluir", methods=["POST"])
@login_necessario
def patrimonio_excluir(item_id):
    db = get_db()
    db.execute("DELETE FROM patrimonio WHERE id = ?", (item_id,))
    db.commit()
    return redirect(url_for("patrimonio"))


# ── Checklist ────────────────────────────────────────────────────────

def _decrypt_tarefa(row, dek: bytes) -> dict:
    def safe(val):
        if not val:
            return ""
        try:
            return decrypt_field(val, dek)
        except Exception:
            return ""
    return {
        "id":        row["id"],
        "texto":     safe(row["texto_enc"]),
        "feito":     safe(row["feito_enc"]) == "1",
        "criado_em": row["criado_em"],
    }


@app.route("/checklist")
@login_necessario
def checklist():
    dek  = get_dek()
    db   = get_db()
    rows = db.execute("SELECT * FROM tarefas ORDER BY criado_em ASC").fetchall()
    tarefas_dec = [_decrypt_tarefa(r, dek) for r in rows]
    # Pendentes primeiro, concluídas por último
    tarefas = [t for t in tarefas_dec if not t["feito"]] + \
              [t for t in tarefas_dec if t["feito"]]
    return render_template("checklist.html", tarefas=tarefas)


@app.route("/checklist/novo", methods=["POST"])
@login_necessario
def checklist_novo():
    from flask import jsonify
    dek    = get_dek()
    data   = request.get_json(silent=True) or {}
    texto  = sanitize(data.get("texto", ""), 500).strip()
    if not texto:
        return jsonify(ok=False), 400
    usuario = session.get("usuario_nome", "")
    db  = get_db()
    cur = db.execute(
        "INSERT INTO tarefas (texto_enc, feito_enc, criado_por_enc) VALUES (?,?,?)",
        (encrypt_field(texto, dek), encrypt_field("0", dek), encrypt_field(usuario, dek)),
    )
    db.commit()
    return jsonify(ok=True, id=cur.lastrowid, texto=texto)


@app.route("/checklist/<int:tid>/toggle", methods=["POST"])
@login_necessario
def checklist_toggle(tid):
    from flask import jsonify
    dek = get_dek()
    db  = get_db()
    row = db.execute("SELECT * FROM tarefas WHERE id = ?", (tid,)).fetchone()
    if not row:
        abort(404)
    t      = _decrypt_tarefa(row, dek)
    novo   = "0" if t["feito"] else "1"
    db.execute("UPDATE tarefas SET feito_enc = ? WHERE id = ?", (encrypt_field(novo, dek), tid))
    db.commit()
    return jsonify(ok=True, feito=novo == "1")


@app.route("/checklist/<int:tid>/excluir", methods=["POST"])
@login_necessario
def checklist_excluir(tid):
    from flask import jsonify
    db = get_db()
    db.execute("DELETE FROM tarefas WHERE id = ?", (tid,))
    db.commit()
    return jsonify(ok=True)


@app.route("/checklist/limpar-concluidas", methods=["POST"])
@login_necessario
def checklist_limpar():
    from flask import jsonify
    dek  = get_dek()
    db   = get_db()
    rows = db.execute("SELECT * FROM tarefas").fetchall()
    ids  = [r["id"] for r in rows if _decrypt_tarefa(r, dek)["feito"]]
    for i in ids:
        db.execute("DELETE FROM tarefas WHERE id = ?", (i,))
    db.commit()
    return jsonify(ok=True, removidos=len(ids))


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
