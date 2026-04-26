import os
import sqlite3
import logging
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, abort, g

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'dev-secret-troque-em-producao')
app.config['DEBUG'] = os.getenv('FLASK_DEBUG', '0') == '1'

DB_PATH = os.path.join(os.path.dirname(__file__), 'orderapp.db')

logging.basicConfig(level=logging.INFO)


# ── DB ──────────────────────────────────────────────────────────

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute('PRAGMA journal_mode=WAL')
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.execute('''
        CREATE TABLE IF NOT EXISTS caixas (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            banco      TEXT NOT NULL,
            data       TEXT,
            valor      REAL NOT NULL DEFAULT 0,
            criado_por TEXT,
            criado_em  TEXT DEFAULT (datetime('now'))
        )
    ''')
    db.execute('''
        CREATE TABLE IF NOT EXISTS usuarios (
            id    INTEGER PRIMARY KEY AUTOINCREMENT,
            login TEXT UNIQUE NOT NULL,
            senha TEXT NOT NULL,
            nome  TEXT NOT NULL
        )
    ''')
    from werkzeug.security import generate_password_hash
    usuarios = [
        ('dantederette', 'dante1946dante1946dante1946', 'Dante Derette'),
        ('admin',        'admin123',                   'Administrador'),
    ]
    for login, senha, nome in usuarios:
        db.execute(
            'INSERT OR IGNORE INTO usuarios (login, senha, nome) VALUES (?, ?, ?)',
            (login, generate_password_hash(senha), nome)
        )
    db.commit()
    db.close()


# ── Auth ─────────────────────────────────────────────────────────

def login_necessario(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('usuario_id'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


def sanitize(val, max_len=200):
    if val is None:
        return ''
    return str(val).strip()[:max_len]


# ── Login ────────────────────────────────────────────────────────

@app.route('/login', methods=['GET', 'POST'])
def login():
    erro = None
    if request.method == 'POST':
        login_val = sanitize(request.form.get('login'), 100)
        senha_val = request.form.get('senha', '')
        from werkzeug.security import check_password_hash
        db = get_db()
        row = db.execute('SELECT * FROM usuarios WHERE login = ?', (login_val,)).fetchone()
        if row and check_password_hash(row['senha'], senha_val):
            session['usuario_id'] = row['id']
            session['usuario_nome'] = row['nome']
            return redirect(url_for('caixas'))
        erro = 'Login ou senha inválidos.'
    return render_template('login.html', erro=erro)


@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/')
def index():
    return redirect(url_for('caixas'))


# ── Caixas ───────────────────────────────────────────────────────

@app.route('/caixas')
@login_necessario
def caixas():
    mes   = sanitize(request.args.get('mes'),   4)
    ano   = sanitize(request.args.get('ano'),   4)
    banco = sanitize(request.args.get('banco'), 150)

    sql = 'SELECT id, banco, data, valor FROM caixas WHERE 1=1'
    params = []
    if mes:
        sql += " AND strftime('%m', data) = ?"
        params.append(mes.zfill(2))
    if ano:
        sql += " AND strftime('%Y', data) = ?"
        params.append(ano)
    if banco:
        sql += ' AND banco = ?'
        params.append(banco)
    sql += ' ORDER BY data DESC'

    db = get_db()
    registros = db.execute(sql, params).fetchall()
    total = sum(float(r['valor'] or 0) for r in registros)
    bancos = [r['banco'] for r in db.execute(
        "SELECT DISTINCT banco FROM caixas WHERE banco IS NOT NULL AND banco != '' ORDER BY banco"
    ).fetchall()]

    # converter Row para dict e parsear data
    caixas_list = []
    for r in registros:
        d = dict(r)
        if d['data']:
            try:
                d['data'] = datetime.strptime(d['data'], '%Y-%m-%d')
            except Exception:
                d['data'] = None
        caixas_list.append(type('Obj', (), d)())

    filtros = {'mes': mes, 'ano': ano, 'banco': banco}
    return render_template('caixas.html', caixas=caixas_list, total=total, filtros=filtros, bancos=bancos)


@app.route('/caixas/novo', methods=['GET'])
@login_necessario
def caixas_novo_form():
    hoje = datetime.now().strftime('%Y-%m-%d')
    return render_template('caixas_form.html', caixa=None, hoje=hoje, erro=None, form=None)


@app.route('/caixas/novo', methods=['POST'])
@login_necessario
def caixas_novo():
    banco  = sanitize(request.form.get('banco'), 150)
    data   = sanitize(request.form.get('data'),  10)
    try:
        valor = round(float(request.form.get('valor') or 0), 2)
    except ValueError:
        valor = 0.0
    usuario = session.get('usuario_nome', '')

    db = get_db()
    cur = db.execute(
        'INSERT INTO caixas (banco, data, valor, criado_por) VALUES (?, ?, ?, ?)',
        (banco, data or None, valor, usuario)
    )
    db.commit()
    new_id = cur.lastrowid
    return redirect(url_for('caixas_editar_form', caixa_id=new_id))


@app.route('/caixas/<int:caixa_id>/editar', methods=['GET'])
@login_necessario
def caixas_editar_form(caixa_id):
    db = get_db()
    row = db.execute('SELECT * FROM caixas WHERE id = ?', (caixa_id,)).fetchone()
    if not row:
        abort(404)
    caixa = dict(row)
    if caixa['data']:
        try:
            caixa['data'] = datetime.strptime(caixa['data'], '%Y-%m-%d')
        except Exception:
            caixa['data'] = None
    caixa_obj = type('Obj', (), caixa)()
    hoje = datetime.now().strftime('%Y-%m-%d')
    return render_template('caixas_form.html', caixa=caixa_obj, hoje=hoje, erro=None, form=None)


@app.route('/caixas/<int:caixa_id>/editar', methods=['POST'])
@login_necessario
def caixas_editar(caixa_id):
    banco = sanitize(request.form.get('banco'), 150)
    data  = sanitize(request.form.get('data'),  10)
    try:
        valor = round(float(request.form.get('valor') or 0), 2)
    except ValueError:
        valor = 0.0
    db = get_db()
    db.execute(
        'UPDATE caixas SET banco=?, data=?, valor=? WHERE id=?',
        (banco, data or None, valor, caixa_id)
    )
    db.commit()
    return redirect(url_for('caixas_editar_form', caixa_id=caixa_id))


@app.route('/caixas/<int:caixa_id>/excluir', methods=['POST'])
@login_necessario
def caixas_excluir(caixa_id):
    db = get_db()
    db.execute('DELETE FROM caixas WHERE id = ?', (caixa_id,))
    db.commit()
    return redirect(url_for('caixas'))


if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)
