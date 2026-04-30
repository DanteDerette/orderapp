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


@app.template_filter("fmt_data")
def fmt_data(s):
    if not s or len(s) < 10:
        return s or ""
    y, m, d = s[:10].split("-")
    return f"{d}/{m}/{y}"


@app.template_filter("fmt_hora")
def fmt_hora(s):
    if not s or len(s) < 16:
        return ""
    return s[11:16]


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

    # Migrations para tarefas
    cols_tarefas = {r[1] for r in db.execute("PRAGMA table_info(tarefas)").fetchall()}
    if "posicao" not in cols_tarefas:
        db.execute("ALTER TABLE tarefas ADD COLUMN posicao INTEGER DEFAULT 0")
        rows_ord = db.execute("SELECT id FROM tarefas ORDER BY criado_em ASC").fetchall()
        for i, r in enumerate(rows_ord):
            db.execute("UPDATE tarefas SET posicao = ? WHERE id = ?", (i, r[0]))
    if "tipo" not in cols_tarefas:
        db.execute("ALTER TABLE tarefas ADD COLUMN tipo TEXT NOT NULL DEFAULT 'diario'")

    db.execute("""
        CREATE TABLE IF NOT EXISTS historico (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            tipo_lista     TEXT NOT NULL DEFAULT 'diario',
            evento         TEXT NOT NULL DEFAULT 'criado',
            texto_enc      TEXT NOT NULL DEFAULT '',
            criado_por_enc TEXT,
            criado_em      TEXT DEFAULT (datetime('now'))
        )
    """)

    db.execute("""
        CREATE TABLE IF NOT EXISTS checklist_conclusoes (
            tarefa_id INTEGER NOT NULL,
            data      TEXT    NOT NULL,
            PRIMARY KEY (tarefa_id, data)
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
                return redirect(url_for("checklist"))
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
    return redirect(url_for("checklist"))


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

def _log_historico(db, dek, tipo_lista, evento, texto):
    usuario = session.get("usuario_nome", "")
    db.execute(
        "INSERT INTO historico (tipo_lista, evento, texto_enc, criado_por_enc) VALUES (?,?,?,?)",
        (tipo_lista, evento, encrypt_field(texto or "", dek), encrypt_field(usuario, dek)),
    )


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
        "tipo":      row["tipo"] if "tipo" in row.keys() else "diario",
    }


@app.route("/checklist")
@login_necessario
def checklist():
    from datetime import date, timedelta
    dek  = get_dek()
    db   = get_db()
    tipo = request.args.get("tipo", "diario")
    if tipo not in ("diario", "semanal", "mensal"):
        tipo = "diario"

    if tipo == "diario":
        hoje_dt  = date.today()
        hoje_str = hoje_dt.isoformat()
        data_param = request.args.get("data", hoje_str)
        try:
            data_dt = date.fromisoformat(data_param)
            if data_dt > hoje_dt:
                data_dt = hoje_dt
        except ValueError:
            data_dt = hoje_dt
        data_str = data_dt.isoformat()
        is_hoje  = data_str == hoje_str

        # Só mostra tarefas que já existiam naquele dia
        rows = db.execute(
            "SELECT * FROM tarefas WHERE tipo = ? AND date(criado_em, 'localtime') <= ? "
            "ORDER BY posicao ASC, criado_em ASC", (tipo, data_str)
        ).fetchall()

        conclusoes = {r[0] for r in db.execute(
            "SELECT tarefa_id FROM checklist_conclusoes WHERE data = ?", (data_str,)
        ).fetchall()}

        # Migração única: primeira vez visualizando hoje — importa feito_enc existente
        if is_hoje and not conclusoes:
            for r in rows:
                t = _decrypt_tarefa(r, dek)
                if t["feito"]:
                    db.execute(
                        "INSERT OR IGNORE INTO checklist_conclusoes (tarefa_id, data) VALUES (?,?)",
                        (t["id"], data_str)
                    )
            db.commit()
            conclusoes = {r[0] for r in db.execute(
                "SELECT tarefa_id FROM checklist_conclusoes WHERE data = ?", (data_str,)
            ).fetchall()}

        tarefas = []
        for r in rows:
            t = _decrypt_tarefa(r, dek)
            t["feito"] = t["id"] in conclusoes
            tarefas.append(t)

        meses = ["jan","fev","mar","abr","mai","jun","jul","ago","set","out","nov","dez"]
        dias  = ["seg","ter","qua","qui","sex","sáb","dom"]
        data_fmt = f"{data_dt.day} {meses[data_dt.month-1]}, {dias[data_dt.weekday()]}"
        data_ant = (data_dt - timedelta(days=1)).isoformat()
        data_seg = (data_dt + timedelta(days=1)).isoformat() if not is_hoje else None

        return render_template("checklist.html",
            tarefas=tarefas, tipo_ativo=tipo,
            data_atual=data_str, data_anterior=data_ant,
            data_seguinte=data_seg, data_formatada=data_fmt,
            is_hoje=is_hoje)
    else:
        rows = db.execute(
            "SELECT * FROM tarefas WHERE tipo = ? ORDER BY posicao ASC, criado_em ASC", (tipo,)
        ).fetchall()
        tarefas = [_decrypt_tarefa(r, dek) for r in rows]
        return render_template("checklist.html",
            tarefas=tarefas, tipo_ativo=tipo,
            data_atual=None, data_anterior=None,
            data_seguinte=None, data_formatada=None,
            is_hoje=True)


@app.route("/checklist/novo", methods=["POST"])
@login_necessario
def checklist_novo():
    from flask import jsonify
    dek    = get_dek()
    data   = request.get_json(silent=True) or {}
    texto  = sanitize(data.get("texto", ""), 500).strip()
    if not texto:
        return jsonify(ok=False), 400
    tipo = data.get("tipo", "diario")
    if tipo not in ("diario", "semanal", "mensal"):
        tipo = "diario"
    usuario = session.get("usuario_nome", "")
    db  = get_db()
    max_pos = db.execute("SELECT COALESCE(MAX(posicao), -1) FROM tarefas WHERE tipo = ?", (tipo,)).fetchone()[0]
    cur = db.execute(
        "INSERT INTO tarefas (texto_enc, feito_enc, criado_por_enc, posicao, tipo) VALUES (?,?,?,?,?)",
        (encrypt_field(texto, dek), encrypt_field("0", dek), encrypt_field(usuario, dek), max_pos + 1, tipo),
    )
    _log_historico(db, dek, tipo, "criado", texto)
    db.commit()
    return jsonify(ok=True, id=cur.lastrowid, texto=texto)


@app.route("/checklist/<int:tid>/toggle", methods=["POST"])
@login_necessario
def checklist_toggle(tid):
    from datetime import date
    from flask import jsonify
    dek = get_dek()
    db  = get_db()
    row = db.execute("SELECT * FROM tarefas WHERE id = ?", (tid,)).fetchone()
    if not row:
        abort(404)
    t = _decrypt_tarefa(row, dek)

    if t["tipo"] == "diario":
        hoje = date.today().isoformat()
        existe = db.execute(
            "SELECT 1 FROM checklist_conclusoes WHERE tarefa_id = ? AND data = ?", (tid, hoje)
        ).fetchone()
        if existe:
            db.execute("DELETE FROM checklist_conclusoes WHERE tarefa_id = ? AND data = ?", (tid, hoje))
            feito = False
        else:
            db.execute("INSERT OR IGNORE INTO checklist_conclusoes (tarefa_id, data) VALUES (?,?)", (tid, hoje))
            feito = True
        _log_historico(db, dek, "diario", "marcado" if feito else "desmarcado", t["texto"])
        db.commit()
        return jsonify(ok=True, feito=feito)
    else:
        novo   = "0" if t["feito"] else "1"
        db.execute("UPDATE tarefas SET feito_enc = ? WHERE id = ?", (encrypt_field(novo, dek), tid))
        _log_historico(db, dek, t["tipo"], "marcado" if novo == "1" else "desmarcado", t["texto"])
        db.commit()
        return jsonify(ok=True, feito=novo == "1")


@app.route("/checklist/<int:tid>/excluir", methods=["POST"])
@login_necessario
def checklist_excluir(tid):
    from flask import jsonify
    dek = get_dek()
    db  = get_db()
    row = db.execute("SELECT * FROM tarefas WHERE id = ?", (tid,)).fetchone()
    if row:
        t = _decrypt_tarefa(row, dek)
        _log_historico(db, dek, t["tipo"], "excluido", t["texto"])
    db.execute("DELETE FROM checklist_conclusoes WHERE tarefa_id = ?", (tid,))
    db.execute("DELETE FROM tarefas WHERE id = ?", (tid,))
    db.commit()
    return jsonify(ok=True)


@app.route("/checklist/limpar-concluidas", methods=["POST"])
@login_necessario
def checklist_limpar():
    from datetime import date
    from flask import jsonify
    dek  = get_dek()
    db   = get_db()
    data = request.get_json(silent=True) or {}
    tipo = data.get("tipo", "diario")
    if tipo not in ("diario", "semanal", "mensal"):
        tipo = "diario"

    if tipo == "diario":
        hoje = date.today().isoformat()
        rows = db.execute(
            "SELECT t.* FROM tarefas t "
            "JOIN checklist_conclusoes c ON c.tarefa_id = t.id "
            "WHERE t.tipo = 'diario' AND c.data = ?", (hoje,)
        ).fetchall()
        feitas = [_decrypt_tarefa(r, dek) for r in rows]
        for t in feitas:
            _log_historico(db, dek, tipo, "excluido", t["texto"])
            db.execute("DELETE FROM checklist_conclusoes WHERE tarefa_id = ?", (t["id"],))
            db.execute("DELETE FROM tarefas WHERE id = ?", (t["id"],))
    else:
        rows = db.execute("SELECT * FROM tarefas WHERE tipo = ?", (tipo,)).fetchall()
        feitas = [_decrypt_tarefa(r, dek) for r in rows if _decrypt_tarefa(r, dek)["feito"]]
        for t in feitas:
            _log_historico(db, dek, tipo, "excluido", t["texto"])
            db.execute("DELETE FROM tarefas WHERE id = ?", (t["id"],))

    db.commit()
    return jsonify(ok=True, removidos=len(feitas))


@app.route("/checklist/<int:tid>/editar", methods=["POST"])
@login_necessario
def checklist_editar(tid):
    from flask import jsonify
    dek  = get_dek()
    data = request.get_json(silent=True) or {}
    texto = sanitize(data.get("texto", ""), 500).strip()
    if not texto:
        return jsonify(ok=False), 400
    db  = get_db()
    row = db.execute("SELECT id FROM tarefas WHERE id = ?", (tid,)).fetchone()
    if not row:
        abort(404)
    row2 = db.execute("SELECT tipo FROM tarefas WHERE id = ?", (tid,)).fetchone()
    tipo = row2["tipo"] if row2 and row2["tipo"] else "diario"
    db.execute("UPDATE tarefas SET texto_enc = ? WHERE id = ?", (encrypt_field(texto, dek), tid))
    _log_historico(db, dek, tipo, "editado", texto)
    db.commit()
    return jsonify(ok=True, texto=texto)


@app.route("/checklist/reordenar", methods=["POST"])
@login_necessario
def checklist_reordenar():
    from flask import jsonify
    data = request.get_json(silent=True) or {}
    ids  = data.get("ids", [])
    if not isinstance(ids, list):
        return jsonify(ok=False), 400
    db = get_db()
    for i, tid in enumerate(ids):
        db.execute("UPDATE tarefas SET posicao = ? WHERE id = ?", (i, int(tid)))
    db.commit()
    return jsonify(ok=True)


@app.route("/checklist/substituir", methods=["POST"])
@login_necessario
def checklist_substituir():
    from flask import jsonify
    dek  = get_dek()
    db   = get_db()
    data = request.get_json(silent=True) or {}
    tipo = data.get("tipo", "diario")
    if tipo not in ("diario", "semanal", "mensal"):
        tipo = "diario"
    tarefas_raw = data.get("tarefas", [])
    if not isinstance(tarefas_raw, list):
        return jsonify(ok=False), 400
    tarefas = [sanitize(str(t), 500).strip() for t in tarefas_raw[:100]]
    tarefas = [t for t in tarefas if t]
    rows = db.execute("SELECT * FROM tarefas WHERE tipo = ?", (tipo,)).fetchall()
    for r in rows:
        t = _decrypt_tarefa(r, dek)
        _log_historico(db, dek, tipo, "excluido", t["texto"])
        db.execute("DELETE FROM checklist_conclusoes WHERE tarefa_id = ?", (t["id"],))
    db.execute("DELETE FROM tarefas WHERE tipo = ?", (tipo,))
    usuario = session.get("usuario_nome", "")
    for i, texto in enumerate(tarefas):
        db.execute(
            "INSERT INTO tarefas (texto_enc, feito_enc, criado_por_enc, posicao, tipo) VALUES (?,?,?,?,?)",
            (encrypt_field(texto, dek), encrypt_field("0", dek), encrypt_field(usuario, dek), i, tipo),
        )
        _log_historico(db, dek, tipo, "criado", texto)
    db.commit()
    return jsonify(ok=True, criados=len(tarefas))


@app.route("/checklist/historico")
@login_necessario
def checklist_historico():
    from collections import OrderedDict
    dek  = get_dek()
    db   = get_db()
    tipo_filtro = request.args.get("tipo", "todos")
    if tipo_filtro not in ("todos", "diario", "semanal", "mensal"):
        tipo_filtro = "todos"

    if tipo_filtro == "todos":
        rows = db.execute("SELECT * FROM historico ORDER BY criado_em DESC").fetchall()
    else:
        rows = db.execute(
            "SELECT * FROM historico WHERE tipo_lista = ? ORDER BY criado_em DESC",
            (tipo_filtro,)
        ).fetchall()

    historico = []
    for r in rows:
        try:
            texto = decrypt_field(r["texto_enc"], dek)
        except Exception:
            texto = ""
        historico.append({
            "tipo_lista": r["tipo_lista"],
            "evento":     r["evento"],
            "texto":      texto,
            "criado_em":  r["criado_em"] or "",
        })

    por_data = OrderedDict()
    for h in historico:
        data = h["criado_em"][:10] if h["criado_em"] else "?"
        if data not in por_data:
            por_data[data] = []
        por_data[data].append(h)

    return render_template("historico_checklist.html",
                           por_data=por_data,
                           tipo_filtro=tipo_filtro)


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
