# heldernobregalabs
CENTRAL DE SOFTWARE
```python
# HLOG_WEB_v1_0.py
# HLOG (WEB) v1.0 — Projeto Flask completo (frontend + backend)
# Programador: Hélder Nóbrega — Todos os direitos reservados.
# RGPD: dados guardados na base de dados do servidor (sem envio para terceiros por defeito).
#
# INSTRUÇÃO ÚNICA:
# 1) Cria um ficheiro "HLOG_WEB_v1_0.py" no teu projeto e cola este conteúdo
# 2) Executa Shift+F10 (ele cria a estrutura toda na pasta atual)
# 3) Depois:
#    - python -m venv venv
#    - venv\Scripts\activate
#    - pip install -r requirements.txt
#    - python app.py
# 4) Para GitHub/Render:
#    - faz commit da pasta gerada "heldernobregalabs"
#    - no Render aponta para o repositório e usa render.yaml
#
# O script abaixo:
# - cria pasta "heldernobregalabs" com todos os ficheiros necessários
# - inclui registo/login, olho password, hashing seguro, gestão motivos,
#   dashboard, mensagens do gestor, suspender/reativar utilizadores
# - logs em blocos 4 linhas/75 chars + CALLID só na última linha

from __future__ import annotations
import os
import textwrap
from pathlib import Path

PROJECT_DIR = Path.cwd() / "heldernobregalabs"
TEMPLATES = PROJECT_DIR / "templates"
STATIC = PROJECT_DIR / "static"

def write(path: Path, content: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")

def main():
    # ------------- requirements.txt -------------
    write(PROJECT_DIR / "requirements.txt", """\
Flask==3.0.3
Flask-Login==0.6.3
Flask-SQLAlchemy==3.1.1
Werkzeug==3.0.3
gunicorn==22.0.0
""")

    # ------------- .gitignore -------------
    write(PROJECT_DIR / ".gitignore", """\
__pycache__/
*.pyc
*.pyo
*.db
*.sqlite
instance/
.env
.venv/
venv/
.idea/
.vscode/
.DS_Store
""")

    # ------------- render.yaml -------------
    write(PROJECT_DIR / "render.yaml", """\
services:
  - type: web
    name: heldernobregalabs
    env: python
    plan: free
    buildCommand: pip install -r requirements.txt
    startCommand: gunicorn app:app
    autoDeploy: true
""")

    # ------------- log_formatter.py -------------
    write(PROJECT_DIR / "log_formatter.py", r'''\
import re
import uuid
import textwrap

def _shorten(text: str) -> str:
    repl = [
        ("relativamente a", ""),
        ("no âmbito de", ""),
        ("de forma a", ""),
        ("foi possível", "pude"),
        ("foi efetuado", "fiz"),
        ("foi efetuada", "fiz"),
        ("encaminhado para análise", "encaminhado p/ análise"),
        ("foi prestada explicação ao cliente", "expliquei ao cliente"),
        ("por favor", ""),
        ("cliente informou que", "cliente indica"),
    ]
    out = " ".join((text or "").split()).strip()
    low = out.lower()
    for a, b in repl:
        low = low.replace(a, b)
    low = re.sub(r"\s+", " ", low).strip()
    return low

def wrap75(text: str):
    text = " ".join((text or "").split()).strip()
    if not text:
        return []
    return textwrap.wrap(text, width=75, break_long_words=False, break_on_hyphens=False)

def build_log(payload: dict) -> dict:
    client = (payload.get("client") or "").strip()
    interlocutor = (payload.get("interlocutor") or "").strip()
    motive = (payload.get("motive") or "").strip()

    situacao = (payload.get("situacao") or "Cliente pediu apoio").strip()
    descricao = (payload.get("descricao") or "").strip()[:900]

    status_final = (payload.get("status_final") or "Encaminhado").strip()
    callid = (payload.get("callid") or "").strip()

    lce = bool(payload.get("lce"))
    val_contacto = bool(payload.get("val_contacto"))
    val_nif = bool(payload.get("val_nif"))
    val_cc = bool(payload.get("val_cc"))
    ab_telco = bool(payload.get("ab_telco"))
    ab_alarme = bool(payload.get("ab_alarme"))

    venda = bool(payload.get("houve_venda"))
    servico_venda = (payload.get("servico_venda") or "").strip()

    if not callid:
        callid = uuid.uuid4().hex[:32].upper()
    else:
        callid = re.sub(r"\s+", "", callid)

    # 4 linhas base
    l1 = f"{client}|{interlocutor} {motive}".strip()
    l2 = _shorten(situacao)

    actions = []
    if val_contacto: actions.append("Validação contacto ok")
    if val_nif: actions.append("Validação NIF ok")
    if val_cc: actions.append("Validação CC ok")
    if ab_telco: actions.append("Abordagem comercial telco")
    if ab_alarme: actions.append("Abordagem comercial alarme")
    if lce: actions.append("Informei condições, ofertas e descontos conforme LCE")
    l3 = _shorten(" | ".join(actions) if actions else "Validei informação em sistema")
    l4 = _shorten(descricao if descricao else "Interação registada conforme informação prestada.")

    blocks = [[l1, l2, l3, l4]]

    if venda and servico_venda:
        blocks.append([
            _shorten("Cliente aceitou proposta comercial"),
            _shorten(f"Venda registada: {servico_venda}"),
            _shorten("Expliquei condições e registei aceitação"),
            _shorten("Seguimento conforme procedimentos internos"),
        ])

    # 1) wrap 75
    raw_lines = []
    for b in blocks:
        for item in b:
            raw_lines.extend(wrap75(item) or [""])

    # remove vazios finais
    while raw_lines and not raw_lines[-1].strip():
        raw_lines.pop()

    compact = [x for x in raw_lines if x.strip()]
    blocked = []

    # 2) blocos de 4 + linha vazia entre blocos
    for i, line in enumerate(compact, start=1):
        blocked.append(line[:75])
        if i % 4 == 0:
            blocked.append("")

    while blocked and blocked[-1] == "":
        blocked.pop()

    # 3) última linha com CALLID
    last = f"{status_final} CALLID|{callid}"
    if len(last) > 75:
        last = f"Encaminhado CALLID|{callid}"
        if len(last) > 75:
            max_callid = 75 - len("Encaminhado CALLID|")
            last = f"Encaminhado CALLID|{callid[:max_callid]}"

    # 4) garantir CALLID como 4ª linha do último bloco
    nonempty = sum(1 for x in blocked if x.strip())
    mod = nonempty % 4
    if mod != 0:
        blocked.extend([""] * (4 - mod))

    final_lines = blocked + [last[:75]]

    check = {
        "all_lines_le_75": all(len(x) <= 75 for x in final_lines),
        "callid_once": sum(1 for x in final_lines if "CALLID|" in x) == 1,
        "callid_last_line": "CALLID|" in final_lines[-1],
    }
    return {"text": "\n".join(final_lines), "callid": callid, "check": check}
''')

    # ------------- models.py -------------
    write(PROJECT_DIR / "models.py", r'''\
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(120), nullable=False)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(16), nullable=False, default="user")  # user/admin
    is_active_flag = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def set_password(self, pw: str):
        self.password_hash = generate_password_hash(pw)

    def check_password(self, pw: str) -> bool:
        return check_password_hash(self.password_hash, pw)

    @property
    def is_active(self):
        return bool(self.is_active_flag)

class Motive(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

class Broadcast(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.String(400), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    created_by = db.Column(db.String(64), nullable=False)

class Call(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    created_by = db.Column(db.String(64), nullable=False)

    client = db.Column(db.String(120))
    interlocutor = db.Column(db.String(120))
    motive = db.Column(db.String(120))

    phone = db.Column(db.String(32))
    email = db.Column(db.String(160))
    nif = db.Column(db.String(16))
    cc = db.Column(db.String(32))

    situacao = db.Column(db.String(240))
    descricao = db.Column(db.String(900))
    status_final = db.Column(db.String(40))
    callid = db.Column(db.String(64), nullable=False)

    log_text = db.Column(db.Text, nullable=False)
''')

    # ------------- app.py -------------
    write(PROJECT_DIR / "app.py", r'''\
import os
import re
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from models import db, User, Motive, Broadcast, Call
from log_formatter import build_log

APP_NAME = "HLOG"
VERSION = "1.0"
AUTHOR = "Hélder Nóbrega"
RGPD_NOTE = "Cumpre RGPD: dados guardados localmente no servidor (sem envio por defeito)."

DEFAULT_MOTIVES = [
    "Avaria - Sem serviço",
    "Avaria - Intermitência",
    "Fatura - Dúvida/Contestação",
    "Mudança de morada",
    "Cancelamento/Rescisão",
    "Alteração de pacote",
    "Informações comerciais",
    "Assistência técnica - Agendamento",
    "Roubo/Perda (cartão/telemóvel)",
    "Outro",
]

SERVICOS_VENDA = [
    "ALARME - Apartamento",
    "ALARME - Rés do chão",
    "ALARME - Moradia",
    "Internet móvel",
    "Cartão móvel",
    "Televisão",
    "Telefone fixo",
    "Internet fixa",
]

STATUS_FINAIS = ["Resolvido", "Encaminhado", "Sem resolução", "Aguarda contacto"]

def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev_secret_change_me")
    app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///hlog.db").replace("postgres://", "postgresql://")
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    db.init_app(app)

    login_manager = LoginManager()
    login_manager.login_view = "login"
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    def ensure_seed():
        # cria tabelas e dados base
        db.create_all()

        # cria motivos default se não existirem
        if Motive.query.count() == 0:
            for m in DEFAULT_MOTIVES:
                db.session.add(Motive(name=m))
            db.session.commit()

        # cria admin default se não existir nenhum admin
        if User.query.filter_by(role="admin").count() == 0:
            # admin / admin123
            admin = User(full_name="Administrador", username="admin", role="admin", is_active_flag=True)
            admin.set_password("admin123")
            db.session.add(admin)
            db.session.commit()

    @app.before_request
    def _boot():
        # garante que está tudo criado
        ensure_seed()

    def is_admin() -> bool:
        return bool(current_user.is_authenticated and current_user.role == "admin")

    def valid_username(u: str) -> bool:
        return bool(re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", u or ""))

    def valid_password(p: str) -> bool:
        return bool(p) and len(p) >= 6

    @app.context_processor
    def inject_globals():
        return dict(APP_NAME=APP_NAME, VERSION=VERSION, AUTHOR=AUTHOR, RGPD_NOTE=RGPD_NOTE)

    @app.get("/")
    def index():
        if current_user.is_authenticated:
            return redirect(url_for("home"))
        return redirect(url_for("login"))

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            full_name = (request.form.get("full_name") or "").strip()
            username = (request.form.get("username") or "").strip()
            password = (request.form.get("password") or "").strip()

            if not full_name:
                flash("Nome é obrigatório.", "danger")
                return redirect(url_for("register"))
            if not valid_username(username):
                flash("Username inválido (3-32; letras/números/._-).", "danger")
                return redirect(url_for("register"))
            if not valid_password(password):
                flash("Password fraca (mínimo 6).", "danger")
                return redirect(url_for("register"))
            if User.query.filter_by(username=username).first():
                flash("Esse username já existe.", "danger")
                return redirect(url_for("register"))

            u = User(full_name=full_name, username=username, role="user", is_active_flag=True)
            u.set_password(password)
            db.session.add(u)
            db.session.commit()

            flash("Conta criada. Faz login.", "success")
            return redirect(url_for("login"))

        return render_template("register.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = (request.form.get("username") or "").strip()
            password = (request.form.get("password") or "").strip()

            u = User.query.filter_by(username=username).first()
            if not u or not u.check_password(password):
                flash("Credenciais inválidas.", "danger")
                return redirect(url_for("login"))
            if not u.is_active_flag:
                flash("Conta suspensa. Contacta a gestão.", "danger")
                return redirect(url_for("login"))

            login_user(u)
            return redirect(url_for("home"))

        return render_template("login.html")

    @app.get("/logout")
    @login_required
    def logout():
        logout_user()
        return redirect(url_for("login"))

    @app.get("/home")
    @login_required
    def home():
        motives = [m.name for m in Motive.query.order_by(Motive.name.asc()).all()]
        return render_template(
            "home.html",
            motives=motives,
            services=SERVICOS_VENDA,
            statuses=STATUS_FINAIS,
        )

    @app.get("/history")
    @login_required
    def history():
        rows = Call.query.order_by(Call.id.desc()).limit(200).all()
        return render_template("history.html", rows=rows)

    # ----------- API: gerar/guardar -----------
    @app.post("/api/generate")
    @login_required
    def api_generate():
        payload = request.get_json(force=True) or {}
        out = build_log(payload)
        return jsonify(out)

    @app.post("/api/save")
    @login_required
    def api_save():
        payload = request.get_json(force=True) or {}
        out = build_log(payload)

        c = Call(
            created_at=datetime.utcnow(),
            created_by=current_user.username,
            client=(payload.get("client") or "").strip(),
            interlocutor=(payload.get("interlocutor") or "").strip(),
            motive=(payload.get("motive") or "").strip(),
            phone=(payload.get("phone") or "").strip(),
            email=(payload.get("email") or "").strip(),
            nif=(payload.get("nif") or "").strip(),
            cc=(payload.get("cc") or "").strip(),
            situacao=(payload.get("situacao") or "").strip()[:240],
            descricao=(payload.get("descricao") or "").strip()[:900],
            status_final=(payload.get("status_final") or "").strip()[:40],
            callid=out["callid"],
            log_text=out["text"],
        )
        db.session.add(c)
        db.session.commit()
        return jsonify({"ok": True, "id": c.id, "callid": out["callid"]})

    # ----------- Admin -----------
    @app.get("/admin")
    @login_required
    def admin_dashboard():
        if not is_admin():
            return "Forbidden", 403

        total_calls = Call.query.count()
        # contagem por motivo
        motives = [m.name for m in Motive.query.order_by(Motive.name.asc()).all()]
        counts = {}
        for m in motives:
            counts[m] = Call.query.filter_by(motive=m).count()

        latest_msgs = Broadcast.query.order_by(Broadcast.id.desc()).limit(20).all()
        suspended = User.query.filter_by(is_active_flag=False).count()
        users_total = User.query.count()

        return render_template(
            "admin_dashboard.html",
            total_calls=total_calls,
            counts=counts,
            users_total=users_total,
            suspended=suspended,
            latest_msgs=latest_msgs
        )

    # ---- motivos ----
    @app.get("/admin/motives")
    @login_required
    def admin_motives():
        if not is_admin():
            return "Forbidden", 403
        motives = Motive.query.order_by(Motive.name.asc()).all()
        return render_template("admin_motives.html", motives=motives)

    @app.post("/admin/motives/add")
    @login_required
    def admin_motives_add():
        if not is_admin():
            return "Forbidden", 403
        name = (request.form.get("name") or "").strip()
        if not name:
            flash("Motivo vazio.", "danger")
            return redirect(url_for("admin_motives"))
        if Motive.query.filter_by(name=name).first():
            flash("Motivo já existe.", "danger")
            return redirect(url_for("admin_motives"))
        db.session.add(Motive(name=name))
        db.session.commit()
        flash("Motivo criado.", "success")
        return redirect(url_for("admin_motives"))

    @app.post("/admin/motives/delete")
    @login_required
    def admin_motives_delete():
        if not is_admin():
            return "Forbidden", 403
        mid = int(request.form.get("id") or "0")
        m = db.session.get(Motive, mid)
        if m:
            db.session.delete(m)
            db.session.commit()
            flash("Motivo removido.", "success")
        return redirect(url_for("admin_motives"))

    # ---- users ----
    @app.get("/admin/users")
    @login_required
    def admin_users():
        if not is_admin():
            return "Forbidden", 403
        users = User.query.order_by(User.created_at.desc()).all()
        return render_template("admin_users.html", users=users)

    @app.post("/admin/users/toggle")
    @login_required
    def admin_users_toggle():
        if not is_admin():
            return "Forbidden", 403
        uid = int(request.form.get("id") or "0")
        u = db.session.get(User, uid)
        if u and u.username != "admin":
            u.is_active_flag = not u.is_active_flag
            db.session.commit()
            flash("Estado do utilizador atualizado.", "success")
        return redirect(url_for("admin_users"))

    @app.post("/admin/users/promote")
    @login_required
    def admin_users_promote():
        if not is_admin():
            return "Forbidden", 403
        uid = int(request.form.get("id") or "0")
        u = db.session.get(User, uid)
        if u and u.username != "admin":
            u.role = "admin" if u.role != "admin" else "user"
            db.session.commit()
            flash("Role atualizado.", "success")
        return redirect(url_for("admin_users"))

    # ---- mensagens ----
    @app.get("/admin/messages")
    @login_required
    def admin_messages():
        if not is_admin():
            return "Forbidden", 403
        msgs = Broadcast.query.order_by(Broadcast.id.desc()).limit(50).all()
        users = User.query.order_by(User.username.asc()).all()
        return render_template("admin_messages.html", msgs=msgs, users=users)

    @app.post("/admin/messages/send")
    @login_required
    def admin_messages_send():
        if not is_admin():
            return "Forbidden", 403
        msg = (request.form.get("message") or "").strip()
        if not msg:
            flash("Mensagem vazia.", "danger")
            return redirect(url_for("admin_messages"))
        b = Broadcast(message=msg[:400], created_by=current_user.username)
        db.session.add(b)
        db.session.commit()
        flash("Mensagem enviada (broadcast).", "success")
        return redirect(url_for("admin_messages"))

    # Poll do utilizador: recebe última mensagem nova
    @app.get("/api/poll_broadcast")
    @login_required
    def poll_broadcast():
        last_id = int(request.args.get("last_id") or "0")
        msg = Broadcast.query.filter(Broadcast.id > last_id).order_by(Broadcast.id.asc()).first()
        if not msg:
            return jsonify({"ok": True, "message": None})
        return jsonify({"ok": True, "message": {"id": msg.id, "text": msg.message, "by": msg.created_by, "at": msg.created_at.isoformat()}})

    return app

app = create_app()

if __name__ == "__main__":
    # local dev
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5055")), debug=False)
''')

    # ------------- templates -------------
    write(TEMPLATES / "base.html", r'''\
<!doctype html>
<html lang="pt-PT">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>{{ APP_NAME }} v{{ VERSION }}</title>
  <link rel="stylesheet" href="{{ url_for('static', filename='styles.css') }}">
</head>
<body>
<header class="topbar">
  <div class="brand">
    <div class="brand__name">{{ APP_NAME }}</div>
    <div class="badge">v{{ VERSION }}</div>
  </div>

  {% if current_user.is_authenticated %}
    <div class="nav">
      <a href="{{ url_for('home') }}">Criar log</a>
      <a href="{{ url_for('history') }}">Histórico</a>
      {% if current_user.role == 'admin' %}
        <a href="{{ url_for('admin_dashboard') }}">Gestão</a>
      {% endif %}
      <a class="btn btn-light" href="{{ url_for('logout') }}">Mudar utilizador</a>
    </div>
  {% endif %}
</header>

<main class="container">
  <div class="meta">
    <span>{{ RGPD_NOTE }}</span>
    <span>•</span>
    <span>Programador: {{ AUTHOR }} — Todos os direitos reservados.</span>
  </div>

  {% with messages = get_flashed_messages(with_categories=True) %}
    {% if messages %}
      <div class="flashes">
        {% for cat, msg in messages %}
          <div class="flash flash-{{ cat }}">{{ msg }}</div>
        {% endfor %}
      </div>
    {% endif %}
  {% endwith %}

  {% block content %}{% endblock %}
</main>

<div id="toast" class="toast" style="display:none"></div>

{% if current_user.is_authenticated %}
<script src="{{ url_for('static', filename='app.js') }}"></script>
{% endif %}
</body>
</html>
''')

    write(TEMPLATES / "login.html", r'''\
{% extends "base.html" %}
{% block content %}
<div class="card narrow">
  <h2>Entrar</h2>
  <form method="post">
    <label>Username</label>
    <input name="username" autocomplete="username" required>

    <label>Password</label>
    <div class="pwwrap">
      <input id="pw" name="password" type="password" autocomplete="current-password" required>
      <button type="button" class="eye" onclick="togglePw('pw', this)">👁</button>
    </div>

    <button class="btn" type="submit">Entrar</button>
  </form>

  <div class="hint">
    Não tens conta? <a href="{{ url_for('register') }}">Registar</a>
  </div>
</div>
{% endblock %}
''')

    write(TEMPLATES / "register.html", r'''\
{% extends "base.html" %}
{% block content %}
<div class="card narrow">
  <h2>Registo</h2>
  <form method="post">
    <label>Nome</label>
    <input name="full_name" required>

    <label>Username (3-32)</label>
    <input name="username" required>

    <label>Password (mín. 6)</label>
    <div class="pwwrap">
      <input id="pw1" name="password" type="password" required>
      <button type="button" class="eye" onclick="togglePw('pw1', this)">👁</button>
    </div>

    <button class="btn" type="submit">Criar conta</button>
  </form>

  <div class="hint">
    Já tens conta? <a href="{{ url_for('login') }}">Entrar</a>
  </div>
</div>
{% endblock %}
''')

    write(TEMPLATES / "home.html", r'''\
{% extends "base.html" %}
{% block content %}
<div class="grid">
  <div class="card">
    <h2>Criar log (IBM AS/400)</h2>

    <div class="row">
      <div class="col">
        <label>Cliente</label>
        <input id="client">
      </div>
      <div class="col">
        <label>Interlocutor</label>
        <input id="interlocutor">
      </div>
    </div>

    <label>Motivo de entrada</label>
    <select id="motive">
      {% for m in motives %}
        <option value="{{m}}">{{m}}</option>
      {% endfor %}
    </select>

    <div class="row">
      <div class="col">
        <label>Contacto</label>
        <input id="phone" placeholder="+3519XXXXXXXX ou 9XXXXXXXX">
      </div>
      <div class="col">
        <label>Email</label>
        <input id="email" placeholder="exemplo@dominio.pt">
      </div>
    </div>

    <div class="row">
      <div class="col">
        <label>NIF</label>
        <input id="nif" placeholder="9 dígitos">
      </div>
      <div class="col">
        <label>CC</label>
        <input id="cc" placeholder="123456789ZZ1">
      </div>
    </div>

    <div class="subcard">
      <b>Check boxes</b>
      <div class="checks">
        <label><input type="checkbox" id="val_contacto"> Validação contactos</label>
        <label><input type="checkbox" id="val_nif"> Validação NIF</label>
        <label><input type="checkbox" id="val_cc"> Validação CC</label>
        <label><input type="checkbox" id="ab_telco"> Abordagem comercial telco</label>
        <label><input type="checkbox" id="ab_alarme"> Abordagem comercial alarme</label>
        <label><input type="checkbox" id="lce"> Linha LCE</label>
      </div>
    </div>

    <label>Situação identificada</label>
    <input id="situacao">

    <label>Descrição (até 900)</label>
    <textarea id="descricao" maxlength="900"></textarea>

    <div class="subcard">
      <b>Venda</b>
      <div class="row">
        <div class="col">
          <label><input type="checkbox" id="houve_venda"> Houve venda</label>
        </div>
        <div class="col">
          <label>Serviço</label>
          <select id="servico_venda">
            {% for s in services %}
              <option value="{{s}}">{{s}}</option>
            {% endfor %}
          </select>
        </div>
      </div>
    </div>

    <div class="row">
      <div class="col">
        <label>Estado final</label>
        <select id="status_final">
          {% for s in statuses %}
            <option value="{{s}}">{{s}}</option>
          {% endfor %}
        </select>
      </div>
      <div class="col">
        <label>CALLID (opcional)</label>
        <input id="callid" placeholder="Se vazio, é gerado automaticamente">
      </div>
    </div>

    <div class="row">
      <button class="btn" onclick="generateLog()">Gerar log</button>
      <button class="btn btn-secondary" onclick="saveLog()">Guardar</button>
    </div>

    <div class="small" id="check_msg"></div>
  </div>

  <div class="card">
    <h2>Pré-visualização</h2>
    <pre id="preview"></pre>
  </div>
</div>
{% endblock %}
''')

    write(TEMPLATES / "history.html", r'''\
{% extends "base.html" %}
{% block content %}
<div class="card">
  <h2>Histórico</h2>
  <table class="table">
    <thead>
      <tr>
        <th>Data</th><th>Utilizador</th><th>Cliente</th><th>Motivo</th><th>CALLID</th>
      </tr>
    </thead>
    <tbody>
    {% for r in rows %}
      <tr>
        <td>{{ r.created_at }}</td>
        <td>{{ r.created_by }}</td>
        <td>{{ r.client or "" }}</td>
        <td>{{ r.motive or "" }}</td>
        <td>{{ r.callid }}</td>
      </tr>
    {% endfor %}
    </tbody>
  </table>
</div>
{% endblock %}
''')

    write(TEMPLATES / "admin_dashboard.html", r'''\
{% extends "base.html" %}
{% block content %}
<div class="grid">
  <div class="card">
    <h2>Dashboard</h2>
    <div class="kpis">
      <div class="kpi"><div class="kpi__n">{{ total_calls }}</div><div class="kpi__l">Chamadas atendidas</div></div>
      <div class="kpi"><div class="kpi__n">{{ users_total }}</div><div class="kpi__l">Utilizadores</div></div>
      <div class="kpi"><div class="kpi__n">{{ suspended }}</div><div class="kpi__l">Suspensos</div></div>
    </div>

    <h3>Motivos registados</h3>
    <table class="table">
      <thead><tr><th>Motivo</th><th>Total</th></tr></thead>
      <tbody>
      {% for m,n in counts.items() %}
        <tr><td>{{m}}</td><td><b>{{n}}</b></td></tr>
      {% endfor %}
      </tbody>
    </table>

    <div class="row">
      <a class="btn btn-secondary" href="{{ url_for('admin_motives') }}">Gerir motivos</a>
      <a class="btn btn-secondary" href="{{ url_for('admin_users') }}">Gerir utilizadores</a>
      <a class="btn btn-secondary" href="{{ url_for('admin_messages') }}">Mensagens</a>
    </div>
  </div>

  <div class="card">
    <h2>Últimas mensagens (broadcast)</h2>
    {% if latest_msgs %}
      <ul class="list">
      {% for m in latest_msgs %}
        <li><b>{{ m.created_by }}</b> — {{ m.message }} <span class="muted">({{ m.created_at }})</span></li>
      {% endfor %}
      </ul>
    {% else %}
      <div class="muted">Sem mensagens.</div>
    {% endif %}
  </div>
</div>
{% endblock %}
''')

    write(TEMPLATES / "admin_motives.html", r'''\
{% extends "base.html" %}
{% block content %}
<div class="card">
  <h2>Gestão de motivos</h2>

  <form method="post" action="{{ url_for('admin_motives_add') }}" class="row">
    <div class="col">
      <label>Novo motivo</label>
      <input name="name" required>
    </div>
    <div class="col" style="align-self:end">
      <button class="btn" type="submit">Adicionar</button>
    </div>
  </form>

  <table class="table">
    <thead><tr><th>Motivo</th><th>Ações</th></tr></thead>
    <tbody>
    {% for m in motives %}
      <tr>
        <td>{{ m.name }}</td>
        <td>
          <form method="post" action="{{ url_for('admin_motives_delete') }}" style="display:inline">
            <input type="hidden" name="id" value="{{ m.id }}">
            <button class="btn btn-danger" type="submit">Remover</button>
          </form>
        </td>
      </tr>
    {% endfor %}
    </tbody>
  </table>

  <a class="btn btn-secondary" href="{{ url_for('admin_dashboard') }}">Voltar</a>
</div>
{% endblock %}
''')

    write(TEMPLATES / "admin_users.html", r'''\
{% extends "base.html" %}
{% block content %}
<div class="card">
  <h2>Gestão de utilizadores</h2>
  <table class="table">
    <thead><tr><th>Nome</th><th>Username</th><th>Role</th><th>Estado</th><th>Ações</th></tr></thead>
    <tbody>
    {% for u in users %}
      <tr>
        <td>{{ u.full_name }}</td>
        <td>{{ u.username }}</td>
        <td><b>{{ u.role }}</b></td>
        <td>
          {% if u.is_active_flag %}
            <span class="pill ok">Ativo</span>
          {% else %}
            <span class="pill bad">Suspenso</span>
          {% endif %}
        </td>
        <td>
          {% if u.username != 'admin' %}
          <form method="post" action="{{ url_for('admin_users_toggle') }}" style="display:inline">
            <input type="hidden" name="id" value="{{ u.id }}">
            <button class="btn btn-secondary" type="submit">
              {% if u.is_active_flag %}Suspender{% else %}Reativar{% endif %}
            </button>
          </form>
          <form method="post" action="{{ url_for('admin_users_promote') }}" style="display:inline">
            <input type="hidden" name="id" value="{{ u.id }}">
            <button class="btn btn-secondary" type="submit">
              {% if u.role != 'admin' %}Promover a admin{% else %}Rebaixar a user{% endif %}
            </button>
          </form>
          {% endif %}
        </td>
      </tr>
    {% endfor %}
    </tbody>
  </table>

  <a class="btn btn-secondary" href="{{ url_for('admin_dashboard') }}">Voltar</a>
</div>
{% endblock %}
''')

    write(TEMPLATES / "admin_messages.html", r'''\
{% extends "base.html" %}
{% block content %}
<div class="grid">
  <div class="card">
    <h2>Consola de mensagens (broadcast)</h2>
    <form method="post" action="{{ url_for('admin_messages_send') }}">
      <label>Mensagem</label>
      <input name="message" maxlength="400" required>
      <button class="btn" type="submit">Enviar</button>
    </form>

    <h3>Histórico</h3>
    {% if msgs %}
      <ul class="list">
      {% for m in msgs %}
        <li><b>{{ m.created_by }}</b> — {{ m.message }} <span class="muted">({{ m.created_at }})</span></li>
      {% endfor %}
      </ul>
    {% else %}
      <div class="muted">Sem mensagens.</div>
    {% endif %}

    <a class="btn btn-secondary" href="{{ url_for('admin_dashboard') }}">Voltar</a>
  </div>

  <div class="card">
    <h2>Utilizadores</h2>
    <div class="muted">A consola atual envia para todos. Para “direto”, cria-se no próximo passo.</div>
    <ul class="list">
    {% for u in users %}
      <li>
        <b>{{ u.username }}</b>
        {% if not u.is_active_flag %}<span class="pill bad">Suspenso</span>{% endif %}
        {% if u.role == 'admin' %}<span class="pill ok">Admin</span>{% endif %}
      </li>
    {% endfor %}
    </ul>
  </div>
</div>
{% endblock %}
''')

    # ------------- static/styles.css -------------
    write(STATIC / "styles.css", r'''\
:root{
  --bg:#f6f7fb;
  --card:#ffffff;
  --ink:#111;
  --muted:#5b5b6a;
  --line:#e7e9f2;
  --primary:#111;
  --danger:#b91c1c;
}

*{box-sizing:border-box}
body{margin:0;font-family:Segoe UI,Arial,sans-serif;background:var(--bg);color:var(--ink)}
a{color:inherit}
.topbar{background:#111;color:#fff;padding:12px 16px;display:flex;align-items:center;justify-content:space-between;gap:12px}
.brand{display:flex;align-items:center;gap:10px}
.brand__name{font-weight:800;letter-spacing:.3px}
.badge{background:#eef2ff;color:#111;border:1px solid #dbe2ff;border-radius:999px;padding:2px 10px;font-size:12px}
.nav{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.nav a{color:#fff;text-decoration:none;opacity:.9}
.nav a:hover{opacity:1}
.container{max-width:1120px;margin:0 auto;padding:16px}
.meta{font-size:12px;color:var(--muted);display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:14px}
.card.narrow{max-width:420px;margin:0 auto}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.row{display:flex;gap:10px;flex-wrap:wrap}
.col{flex:1;min-width:220px}
label{display:block;font-size:13px;color:var(--muted);margin-top:10px;margin-bottom:6px}
input,select,textarea{width:100%;padding:9px 10px;border:1px solid #d7dbe8;border-radius:12px;font:inherit}
textarea{min-height:120px;resize:vertical}
pre{white-space:pre-wrap;background:#0b1020;color:#e5e7eb;padding:12px;border-radius:12px;overflow:auto}
.btn{background:var(--primary);color:#fff;border:0;border-radius:12px;padding:10px 12px;cursor:pointer;margin-top:12px;text-decoration:none;display:inline-block}
.btn:hover{filter:brightness(.95)}
.btn-secondary{background:#4b5563}
.btn-danger{background:var(--danger)}
.btn-light{background:#fff;color:#111}
.subcard{margin-top:12px;padding:12px;border-radius:12px;border:1px solid var(--line);background:#fafbff}
.checks{display:flex;gap:10px;flex-wrap:wrap;margin-top:8px}
.checks label{margin:0;color:#111;font-size:13px}
.small{font-size:12px;color:var(--muted);margin-top:10px}
.table{width:100%;border-collapse:collapse;margin-top:10px}
.table th,.table td{border-bottom:1px solid #eef0f6;text-align:left;padding:8px;font-size:13px}
.kpis{display:flex;gap:10px;flex-wrap:wrap;margin:10px 0}
.kpi{flex:1;min-width:160px;border:1px solid var(--line);border-radius:12px;padding:10px;background:#fafbff}
.kpi__n{font-size:22px;font-weight:800}
.kpi__l{font-size:12px;color:var(--muted)}
.list{padding-left:18px}
.muted{color:var(--muted);font-size:12px}
.pill{display:inline-block;padding:2px 10px;border-radius:999px;border:1px solid var(--line);font-size:12px}
.pill.ok{background:#ecfeff;color:#0f766e;border-color:#99f6e4}
.pill.bad{background:#fef2f2;color:#991b1b;border-color:#fecaca}
.flashes{margin:10px 0}
.flash{padding:10px 12px;border-radius:12px;border:1px solid var(--line);margin-bottom:8px;background:#fff}
.flash-success{border-color:#99f6e4;background:#ecfeff}
.flash-danger{border-color:#fecaca;background:#fef2f2}
.pwwrap{display:flex;gap:8px;align-items:center}
.eye{margin-top:0;height:40px;border-radius:12px;border:1px solid var(--line);background:#fff;cursor:pointer}
.toast{position:fixed;right:12px;bottom:12px;background:#111;color:#fff;padding:10px 12px;border-radius:12px;max-width:420px}
@media (max-width: 920px){.grid{grid-template-columns:1fr}}
''')

    # ------------- static/app.js -------------
    write(STATIC / "app.js", r'''\
function togglePw(id, btn){
  const el = document.getElementById(id);
  if(!el) return;
  el.type = (el.type === "password") ? "text" : "password";
  btn.textContent = (el.type === "password") ? "👁" : "🙈";
}

function toast(msg){
  const t = document.getElementById("toast");
  if(!t) return;
  t.textContent = msg;
  t.style.display = "block";
  setTimeout(()=>{ t.style.display="none"; }, 6000);
}

async function api(path, body){
  const r = await fetch(path, {
    method:"POST",
    headers: {"Content-Type":"application/json"},
    body: JSON.stringify(body)
  });
  return await r.json();
}

function payload(){
  const g = (id)=>document.getElementById(id);
  return {
    client: g("client")?.value || "",
    interlocutor: g("interlocutor")?.value || "",
    motive: g("motive")?.value || "",
    phone: g("phone")?.value || "",
    email: g("email")?.value || "",
    nif: g("nif")?.value || "",
    cc: g("cc")?.value || "",
    situacao: g("situacao")?.value || "",
    descricao: g("descricao")?.value || "",
    status_final: g("status_final")?.value || "",
    callid: g("callid")?.value || "",
    val_contacto: !!g("val_contacto")?.checked,
    val_nif: !!g("val_nif")?.checked,
    val_cc: !!g("val_cc")?.checked,
    ab_telco: !!g("ab_telco")?.checked,
    ab_alarme: !!g("ab_alarme")?.checked,
    lce: !!g("lce")?.checked,
    houve_venda: !!g("houve_venda")?.checked,
    servico_venda: g("servico_venda")?.value || ""
  };
}

async function generateLog(){
  const out = await api("/api/generate", payload());
  const pre = document.getElementById("preview");
  if(pre) pre.textContent = out.text || "";
  const c = out.check || {};
  const msg = document.getElementById("check_msg");
  if(msg){
    msg.innerHTML = `Checklist: linhas≤75=${c.all_lines_le_75} | CALLID 1x=${c.callid_once} | CALLID última=${c.callid_last_line}`;
  }
}

async function saveLog(){
  const out = await api("/api/save", payload());
  if(out && out.ok){
    toast("Guardado. ID: "+out.id+" | CALLID: "+out.callid);
  } else {
    toast("Erro ao guardar.");
  }
}

// Poll de mensagens broadcast
let lastBroadcastId = 0;
async function pollBroadcast(){
  try{
    const r = await fetch("/api/poll_broadcast?last_id="+lastBroadcastId);
    const d = await r.json();
    if(d && d.ok && d.message){
      lastBroadcastId = d.message.id;
      toast("Mensagem da gestão: " + d.message.text);
    }
  }catch(e){}
  setTimeout(pollBroadcast, 2500);
}
pollBroadcast();
''')

    print("\nOK — Projeto criado em:")
    print(PROJECT_DIR)
    print("\nPróximo passo:")
    print("1) cd heldernobregalabs")
    print("2) python -m venv venv")
    print("3) venv\\Scripts\\activate")
    print("4) pip install -r requirements.txt")
    print("5) python app.py")

if __name__ == "__main__":
    main()
```
