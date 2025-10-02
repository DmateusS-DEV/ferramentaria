# app.py
# ============================================================
# Ferramentaria - Aplicação Flask (refatorada e corrigida)
# ============================================================

from functools import wraps
import io
import os
import calendar
import unicodedata
from datetime import date

import pandas as pd
from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, abort, send_file, jsonify, session
)
from flask_bcrypt import Bcrypt
from flask_login import (
    LoginManager, login_user, logout_user,
    login_required, UserMixin, current_user
)

from db import query  # função helper que executa SQL e retorna dicts

# Carrega variáveis de ambiente (se .env existir)
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

# ============================================================
# Inicialização
# ============================================================
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "chave_super_secreta_insegura_mude_isso")

bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = None  # não mostrar texto padrão do Flask-Login

# ============================================================
# Pergunta de Segurança (config + helpers)
# ============================================================
PERGUNTAS_SEGURANCA = [
    "Nome da sua mãe",
    "Cidade onde você nasceu",
    "Nome do seu primeiro animal de estimação",
    "Time do coração",
    "Mês e ano do seu primeiro emprego (ex.: 03/2005)",
    "Comida favorita",
]

def _norm_resposta(txt: str) -> str:
    """Normaliza resposta (remove acentos/espaços e minúsculas)."""
    if not txt:
        return ""
    t = unicodedata.normalize("NFKD", txt.strip().lower())
    t = "".join(ch for ch in t if not unicodedata.combining(ch))
    return " ".join(t.split())

# ============================================================
# Model de Usuário (Flask-Login)
# ============================================================
class User(UserMixin):
    def __init__(self, id_usuario, nome, email, perfil):
        self.id = id_usuario
        self.nome = nome
        self.email = email
        self.perfil = perfil

@login_manager.user_loader
def load_user(user_id):
    u = query("SELECT * FROM usuarios WHERE id_usuario=%s", (user_id,), fetchone=True)
    if not u:
        return None
    return User(u["id_usuario"], u["nome"], u["email"], u["perfil"])

# ============================================================
# Helpers / Utilitários
# ============================================================
def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated or current_user.perfil != "admin":
            abort(403)
        return f(*args, **kwargs)
    return wrapper

@app.errorhandler(403)
def acesso_negado(e):
    return render_template("403.html"), 403

def make_excel_response(rows, filename, sheet_name="Planilha"):
    """Converte rows em Excel e retorna send_file."""
    df = pd.DataFrame(rows or [])
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name=sheet_name)
    output.seek(0)
    return send_file(
        output,
        as_attachment=True,
        download_name=filename,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )

def safe_get_one(sql, params=None, default=0):
    """Executa SELECT 1 linha e devolve int/float seguro."""
    row = query(sql, params or [], fetchone=True)
    if not row:
        return default
    v = next(iter(row.values()))
    try:
        return int(v)
    except Exception:
        try:
            return float(v)
        except Exception:
            return default

def _safe_next(default_endpoint="index"):
    """URL interna segura: prioriza ?next=..., depois referrer, senão default."""
    nxt = request.args.get("next")
    if nxt and nxt.startswith("/"):
        return nxt
    if request.referrer and request.referrer.startswith(request.host_url):
        return request.referrer
    return url_for(default_endpoint)

# ============================================================
# Autenticação
# ============================================================
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        senha = request.form.get("senha", "")
        u = query("SELECT * FROM usuarios WHERE email=%s", (email,), fetchone=True)

        if u and bcrypt.check_password_hash(u["senha"], senha):
            login_user(User(u["id_usuario"], u["nome"], u["email"], u["perfil"]))
            nxt = request.args.get("next")
            if nxt and nxt.startswith("/"):
                return redirect(nxt)
            return redirect(url_for("index"))

        flash("E-mail ou senha incorretos", "danger")

    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

# ============================================================
# Perfil do usuário (autogerenciado)
# ============================================================
@app.route("/perfil", methods=["GET", "POST"])
@login_required
def perfil():
    # Busca dados do usuário logado (inclui hash da senha para validações)
    u = query("""
        SELECT id_usuario, nome, email, perfil, centro_custo, funcao, senha
        FROM usuarios
        WHERE id_usuario=%s
    """, (current_user.id,), fetchone=True)

    if request.method == "POST":
        # ---------- Troca de senha (todos podem) ----------
        senha_atual = (request.form.get("senha_atual") or "").strip()
        nova        = (request.form.get("nova_senha") or "").strip()
        conf        = (request.form.get("confirma_senha") or "").strip()
        trocou_senha = False

        if any([senha_atual, nova, conf]):  # tentou trocar senha
            if not (senha_atual and nova and conf):
                flash("Preencha todos os campos de senha.", "warning")
                return redirect(url_for("perfil"))
            if not bcrypt.check_password_hash(u["senha"], senha_atual):
                flash("Senha atual incorreta.", "danger")
                return redirect(url_for("perfil"))
            if len(nova) < 6:
                flash("A nova senha deve ter pelo menos 6 caracteres.", "warning")
                return redirect(url_for("perfil"))
            if bcrypt.check_password_hash(u["senha"], nova):
                flash("A nova senha não pode ser igual à atual.", "warning")
                return redirect(url_for("perfil"))
            if nova != conf:
                flash("A confirmação da nova senha não confere.", "warning")
                return redirect(url_for("perfil"))

            novo_hash = bcrypt.generate_password_hash(nova).decode("utf-8")
            query("UPDATE usuarios SET senha=%s WHERE id_usuario=%s",
                  (novo_hash, current_user.id), commit=True)
            trocou_senha = True

        # ---------- Atualização de dados ----------
        updates, params = [], []

        # Nome: qualquer usuário pode alterar
        nome = (request.form.get("nome") or "").strip()
        if nome and nome != (u["nome"] or ""):
            updates.append("nome=%s")
            params.append(nome)

        # Email / centro_custo / funcao: apenas ADMIN
        if current_user.perfil == "admin":
            email        = (request.form.get("email") or "").strip()
            centro_custo = (request.form.get("centro_custo") or "").strip() or None
            funcao       = (request.form.get("funcao") or "").strip() or None

            if email and email != (u["email"] or ""):
                updates.append("email=%s")
                params.append(email)
            updates.append("centro_custo=%s"); params.append(centro_custo)
            updates.append("funcao=%s");       params.append(funcao)
        else:
            # Se veio algo nesses campos, ignoramos e avisamos
            if any([
                (request.form.get("email") or "").strip(),
                (request.form.get("centro_custo") or "").strip(),
                (request.form.get("funcao") or "").strip()
            ]):
                flash("Somente administradores podem alterar e-mail, centro de custo e função.", "info")

        if updates:
            params.append(current_user.id)
            query(f"UPDATE usuarios SET {', '.join(updates)} WHERE id_usuario=%s",
                  tuple(params), commit=True)

        if trocou_senha and updates:
            flash("Senha e dados atualizados.", "success")
        elif trocou_senha:
            flash("Senha alterada com sucesso.", "success")
        elif updates:
            flash("Dados atualizados.", "success")

        return redirect(url_for("perfil"))

    return render_template("perfil.html", u=u, is_admin=(current_user.perfil == "admin"))

# ============================================================
# Pergunta de Segurança — Rotas
# ============================================================
@app.route("/perfil/pergunta", methods=["GET", "POST"])
@login_required
def definir_pergunta_seg():
    """Usuário define/atualiza sua pergunta e resposta de segurança."""
    if request.method == "POST":
        pergunta = request.form.get("pergunta") or ""
        resposta = request.form.get("resposta") or ""

        if not pergunta or not resposta:
            flash("Informe a pergunta e a resposta.", "warning")
            return redirect(request.url)

        resposta_norm = _norm_resposta(resposta)
        resposta_hash = bcrypt.generate_password_hash(resposta_norm).decode("utf-8")

        query(
            "UPDATE usuarios SET pergunta_seg=%s, resposta_seg=%s WHERE id_usuario=%s",
            (pergunta, resposta_hash, current_user.id),
            commit=True,
        )
        flash("Pergunta de segurança definida!", "success")
        return redirect(url_for("perfil"))

    u = query("SELECT pergunta_seg FROM usuarios WHERE id_usuario=%s",
              (current_user.id,), fetchone=True) or {}
    return render_template(
        "definir_pergunta.html",
        perguntas=PERGUNTAS_SEGURANCA,
        pergunta_atual=u.get("pergunta_seg")
    )

@app.route("/senha/pergunta", methods=["GET", "POST"])
def recuperar_por_pergunta():
    """
    Fluxo:
      step=1 (GET/POST): digita e-mail
      step=2 (POST): mostra pergunta cadastrada
      step=3 (POST): valida resposta e salva nova senha
    """
    # Step 1
    if request.method == "GET" or request.form.get("step") == "1":
        session.pop("rp_uid", None)
        session.pop("rp_q", None)
        return render_template("recuperar_pergunta.html", step=1)

    # Step 2
    if request.form.get("step") == "2":
        email = (request.form.get("email") or "").strip().lower()
        u = query(
            "SELECT id_usuario, pergunta_seg, resposta_seg FROM usuarios WHERE email=%s",
            (email,), fetchone=True
        )
        if not u or not u["pergunta_seg"] or not u["resposta_seg"]:
            flash("Se o e-mail estiver cadastrado e com pergunta definida, mostraremos a pergunta.", "info")
            return redirect(url_for("recuperar_por_pergunta"))

        session["rp_uid"] = int(u["id_usuario"])
        session["rp_q"] = u["pergunta_seg"]
        return render_template("recuperar_pergunta.html", step=2, pergunta=u["pergunta_seg"], email=email)

    # Step 3
    if request.form.get("step") == "3":
        uid = session.get("rp_uid")
        pergunta = session.get("rp_q")
        if not uid or not pergunta:
            flash("Sessão expirada. Tente novamente.", "warning")
            return redirect(url_for("recuperar_por_pergunta"))

        resposta = _norm_resposta(request.form.get("resposta") or "")
        nova = request.form.get("nova_senha") or ""
        conf = request.form.get("confirma_senha") or ""

        if not nova or nova != conf:
            flash("As senhas não conferem.", "warning")
            return render_template("recuperar_pergunta.html", step=2, pergunta=pergunta)

        row = query("SELECT resposta_seg FROM usuarios WHERE id_usuario=%s", (uid,), fetchone=True)
        if not row or not bcrypt.check_password_hash(row["resposta_seg"], resposta):
            flash("Resposta incorreta.", "danger")
            return render_template("recuperar_pergunta.html", step=2, pergunta=pergunta)

        novo_hash = bcrypt.generate_password_hash(nova).decode("utf-8")
        query("UPDATE usuarios SET senha=%s WHERE id_usuario=%s", (novo_hash, uid), commit=True)

        session.pop("rp_uid", None)
        session.pop("rp_q", None)
        flash("Senha redefinida. Faça login com a nova senha.", "success")
        return redirect(url_for("login"))

    # fallback
    return redirect(url_for("recuperar_por_pergunta"))

# ============================================================
# Dashboard ("/")
# ============================================================
def get_dashboard_kpis():
    """Calcula KPIs do painel (compatível com ONLY_FULL_GROUP_BY)."""
    total_agregados = safe_get_one("SELECT COUNT(*) AS c FROM agregados")
    total_ferramentas = safe_get_one("SELECT COUNT(*) AS c FROM ferramentas")
    qtd_itens = total_agregados + total_ferramentas

    abaixo_min = safe_get_one("""
        SELECT COUNT(*) AS c
        FROM (
          SELECT
            t.nome,
            IFNULL(t.aplicacao,'') AS aplicacao,
            MAX(t.estoque_min) AS estoque_min,
            SUM(a.status='Disponível') AS disponiveis
          FROM agregado_tipos t
          LEFT JOIN agregados a
            ON a.nome=t.nome
           AND IFNULL(a.aplicacao,'') = IFNULL(t.aplicacao,'')
          GROUP BY t.nome, IFNULL(t.aplicacao,'')
        ) x
        WHERE x.estoque_min IS NOT NULL AND x.disponiveis < x.estoque_min
    """)

    acima_max = safe_get_one("""
        SELECT COUNT(*) AS c
        FROM (
          SELECT
            t.nome,
            IFNULL(t.aplicacao,'') AS aplicacao,
            MAX(t.estoque_max) AS estoque_max,
            SUM(a.status='Disponível') AS disponiveis
          FROM agregado_tipos t
          LEFT JOIN agregados a
            ON a.nome=t.nome
           AND IFNULL(a.aplicacao,'') = IFNULL(t.aplicacao,'')
          GROUP BY t.nome, IFNULL(t.aplicacao,'')
        ) x
        WHERE x.estoque_max IS NOT NULL AND x.disponiveis > x.estoque_max
    """)

    baixa_rot = safe_get_one("""
        SELECT COUNT(*) AS c
        FROM agregados a
        LEFT JOIN (
          SELECT COALESCE(id_agregado, 0) AS id_agregado, MAX(data_mov) AS ultima
          FROM movimentacoes
          WHERE id_agregado IS NOT NULL
          GROUP BY id_agregado
        ) m ON m.id_agregado = a.id_agregado
        WHERE (m.ultima IS NULL OR DATEDIFF(CURDATE(), m.ultima) >= 60)
    """)

    return {
        "qtd_itens": qtd_itens,
        "abaixo_min": abaixo_min,
        "acima_max": acima_max,
        "baixa_rot": baixa_rot,
    }

def get_saidas_devolucoes_mes():
    """Retorna (labels, series) com quantidades diárias (somente agregados)."""
    today = date.today()
    ano, mes = today.year, today.month

    rows = query("""
        SELECT
            DAY(data_mov) AS dia,
            SUM(CASE WHEN tipo='saida'     THEN quantidade ELSE 0 END) AS saidas,
            SUM(CASE WHEN tipo='devolucao' THEN quantidade ELSE 0 END) AS devolucoes
        FROM movimentacoes
        WHERE YEAR(data_mov)=%s
          AND MONTH(data_mov)=%s
          AND id_agregado IS NOT NULL
        GROUP BY DAY(data_mov)
        ORDER BY dia
    """, (ano, mes))

    days = calendar.monthrange(ano, mes)[1]
    labels = [f"{d:02d}" for d in range(1, days + 1)]
    saidas = [0] * days
    devolucoes = [0] * days

    for r in rows or []:
        i = int(r["dia"]) - 1
        saidas[i] = int(r["saidas"] or 0)
        devolucoes[i] = int(r["devolucoes"] or 0)

    return labels, {"saidas": saidas, "devolucoes": devolucoes}

from flask import redirect, url_for  # (garanta que estas imports estão no topo)
# from flask_login import current_user  # já existe no seu app.py; se não, mantenha

@app.route("/")
def root():
    # Se já estiver logado, mostra o dashboard
    if current_user.is_authenticated:
        kpi = get_dashboard_kpis()
        labels, series = get_saidas_devolucoes_mes()
        return render_template("index.html", kpi=kpi, labels=labels, series=series)
    # Senão, manda para a tela de login
    return redirect(url_for("login"))

# ============================================================
# Usuários (admin)
# ============================================================
@app.route("/usuarios")
@login_required
@admin_required
def listar_usuarios():
    usuarios = query("""
        SELECT id_usuario, nome, email, perfil, centro_custo, funcao
        FROM usuarios
        ORDER BY id_usuario
    """)
    return render_template("usuarios.html", usuarios=usuarios)

@app.route("/usuarios/novo", methods=["GET", "POST"])
@login_required
@admin_required
def novo_usuario():
    if request.method == "POST":
        nome  = request.form["nome"].strip()
        email = request.form["email"].strip().lower()
        senha = request.form["senha"]
        perfil = request.form["perfil"]
        centro_custo = (request.form.get("centro_custo") or "").strip() or None
        funcao = (request.form.get("funcao") or "").strip() or None

        senha_hash = bcrypt.generate_password_hash(senha).decode("utf-8")
        query(
            "INSERT INTO usuarios (nome,email,senha,perfil,centro_custo,funcao) "
            "VALUES (%s,%s,%s,%s,%s,%s)",
            (nome, email, senha_hash, perfil, centro_custo, funcao),
            commit=True,
        )
        flash("Usuário criado!", "success")
        return redirect(url_for("listar_usuarios"))

    return render_template("novo_usuario.html")

@app.route("/usuarios/editar/<int:id_usuario>", methods=["GET", "POST"])
@login_required
@admin_required
def editar_usuario(id_usuario):
    usuario = query("SELECT * FROM usuarios WHERE id_usuario=%s", (id_usuario,), fetchone=True)
    if not usuario:
        flash("Usuário não encontrado.", "warning")
        return redirect(url_for("listar_usuarios"))

    if request.method == "POST":
        nome         = request.form["nome"]
        email        = request.form["email"]
        perfil       = request.form["perfil"]
        nova_senha   = request.form.get("senha", "")
        centro_custo = (request.form.get("centro_custo") or "").strip() or None
        funcao       = (request.form.get("funcao") or "").strip() or None

        if nova_senha:
            senha_hash = bcrypt.generate_password_hash(nova_senha).decode("utf-8")
            query("""
                UPDATE usuarios
                   SET nome=%s,email=%s,senha=%s,perfil=%s,centro_custo=%s,funcao=%s
                 WHERE id_usuario=%s
            """, (nome, email, senha_hash, perfil, centro_custo, funcao, id_usuario), commit=True)
        else:
            query("""
                UPDATE usuarios
                   SET nome=%s,email=%s,perfil=%s,centro_custo=%s,funcao=%s
                 WHERE id_usuario=%s
            """, (nome, email, perfil, centro_custo, funcao, id_usuario), commit=True)

        flash("Usuário atualizado!", "success")
        return redirect(url_for("listar_usuarios"))

    return render_template("editar_usuario.html", usuario=usuario)

@app.route("/usuarios/excluir/<int:id_usuario>")
@login_required
@admin_required
def excluir_usuario(id_usuario):
    query("DELETE FROM usuarios WHERE id_usuario=%s", (id_usuario,), commit=True)
    flash("Usuário excluído.", "info")
    return redirect(url_for("listar_usuarios"))

# ============================================================
# Agregados (TIPOS + ITENS)
# ============================================================
@app.route("/agregados")
@app.route("/agregados/tipos", endpoint="listar_agregados_tipos")
@login_required
def listar_agregados_tipos():
    q = request.args.get("q", "").strip()
    status = request.args.get("status", "").strip()

    params, where = [], []
    if q:
        where.append("(a.nome LIKE %s OR IFNULL(a.aplicacao,'') LIKE %s)")
        params += [f"%{q}%", f"%{q}%"]
    if status:
        where.append("a.status = %s")
        params.append(status)

    where_sql = " WHERE " + " AND ".join(where) if where else ""

    tipos = query(f"""
        SELECT 
            a.nome,
            a.aplicacao,
            SUM(a.status='Disponível') AS disponiveis,
            COALESCE(t.estoque_min, NULL) AS estoque_min,
            COALESCE(t.estoque_max, NULL) AS estoque_max
        FROM agregados a
        LEFT JOIN agregado_tipos t 
               ON t.nome=a.nome AND IFNULL(t.aplicacao,'') = IFNULL(a.aplicacao,'')
        {where_sql}
        GROUP BY a.nome, a.aplicacao, t.estoque_min, t.estoque_max
        ORDER BY a.nome, a.aplicacao
    """, params)

    resumo = query(f"""
        SELECT COUNT(*) total,
               SUM(status='Disponível') disponiveis,
               SUM(status='Aplicado') aplicados,
               SUM(status='Em reforma') em_reforma,
               SUM(status='Descartado') descartados
        FROM agregados a
        {where_sql}
    """, params, fetchone=True) or {}

    filtros = {"q": q, "status": status}
    return render_template("agregados_tipos.html", tipos=tipos, filtros=filtros, resumo=resumo)

@app.route("/agregados/excel")
@login_required
def exportar_agregados_tipos_excel():
    q = request.args.get("q", "").strip()
    status = request.args.get("status", "").strip()

    params, where = [], []
    if q:
        where.append("(a.nome LIKE %s OR IFNULL(a.aplicacao,'') LIKE %s)")
        params += [f"%{q}%", f"%{q}%"]
    if status:
        where.append("a.status = %s")
        params.append(status)
    where_sql = " WHERE " + " AND ".join(where) if where else ""

    rows = query(f"""
        SELECT 
            a.nome         AS descricao,
            a.aplicacao    AS aplicacao,
            SUM(a.status='Disponível') AS disponiveis,
            COALESCE(t.estoque_min, NULL) AS estoque_min,
            COALESCE(t.estoque_max, NULL) AS estoque_max
        FROM agregados a
        LEFT JOIN agregado_tipos t 
               ON t.nome=a.nome AND IFNULL(t.aplicacao,'') = IFNULL(a.aplicacao,'')
        {where_sql}
        GROUP BY a.nome, a.aplicacao, t.estoque_min, t.estoque_max
        ORDER BY a.nome, a.aplicacao
    """, params)

    return make_excel_response(rows, "agregados_tipos.xlsx", sheet_name="Tipos")

@app.route("/agregados/tipo")
@login_required
def listar_agregados_itens():
    g_nome = request.args.get("nome", "").strip()
    g_apl  = request.args.get("aplicacao", "").strip()
    if not g_nome:
        flash("Selecione um tipo válido.", "warning")
        return redirect(url_for("listar_agregados_tipos"))

    itens = query("""
        SELECT id_agregado, tag, nome, aplicacao, status, localizacao, aplicado_em
        FROM agregados
        WHERE nome=%s AND IFNULL(aplicacao,'') = IFNULL(%s,'')
        ORDER BY FIELD(status,'Disponível','Aplicado','Em reforma','Descartado'), tag
    """, (g_nome, g_apl))

    return render_template("agregados_itens.html", nome=g_nome, aplicacao=g_apl, itens=itens)

@app.route("/agregados/tipo/excel")
@login_required
def exportar_agregados_itens_excel():
    g_nome = request.args.get("nome", "").strip()
    g_apl  = request.args.get("aplicacao", "").strip()
    if not g_nome:
        flash("Selecione um tipo válido.", "warning")
        return redirect(url_for("listar_agregados_tipos"))

    rows = query("""
        SELECT tag, nome, aplicacao, status, localizacao, aplicado_em
        FROM agregados
        WHERE nome=%s AND IFNULL(aplicacao,'') = IFNULL(%s,'')
        ORDER BY FIELD(status,'Disponível','Aplicado','Em reforma','Descartado'), tag
    """, (g_nome, g_apl))

    return make_excel_response(rows, f"agregados_itens_{g_nome}.xlsx", sheet_name="Itens")

@app.route("/agregados/novo", methods=["GET", "POST"])
@login_required
@admin_required
def novo_agregado():
    if request.method == "POST":
        query("""
            INSERT INTO agregados (tag, nome, aplicacao, localizacao, status, aplicado_em)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (
            request.form["tag"],
            request.form["nome"],
            request.form.get("aplicacao"),
            request.form.get("localizacao"),
            request.form.get("status", "Disponível"),
            request.form.get("aplicado_em"),
        ), commit=True)
        flash("Agregado criado!", "success")
        return redirect(url_for("listar_agregados_tipos"))

    return render_template("novo_agregado.html")

@app.route("/agregados/editar/<int:id_agregado>", methods=["GET", "POST"])
@login_required
@admin_required
def editar_agregado(id_agregado):
    agregado = query("SELECT * FROM agregados WHERE id_agregado=%s", (id_agregado,), fetchone=True)
    if not agregado:
        flash("Agregado não encontrado.", "warning")
        return redirect(url_for("listar_agregados_tipos"))

    if request.method == "POST":
        query("""
            UPDATE agregados
               SET tag=%s,
                   nome=%s,
                   aplicacao=%s,
                   localizacao=%s,
                   status=%s,
                   aplicado_em=%s
             WHERE id_agregado=%s
        """, (
            request.form["tag"],
            request.form["nome"],
            request.form.get("aplicacao"),
            request.form.get("localizacao"),
            request.form.get("status", "Disponível"),
            request.form.get("aplicado_em"),
            id_agregado
        ), commit=True)
        flash("Agregado atualizado!", "success")
        return redirect(url_for("listar_agregados_tipos"))

    return render_template("editar_agregado.html", agregado=agregado)

@app.route("/agregados/descartar/<int:id_agregado>", methods=["POST"])
@login_required
@admin_required
def descartar_agregado(id_agregado):
    # 1) Marca como descartado
    query("""
        UPDATE agregados
           SET status='Descartado',
               aplicado_em=NULL
         WHERE id_agregado=%s
    """, (id_agregado,), commit=True)

    # 2) Registra no relatório (tabela movimentacoes)
    query("""
        INSERT INTO movimentacoes
            (tipo, id_agregado, id_ferramenta, quantidade, id_usuario, observacao)
        VALUES
            (%s,   %s,          %s,            %s,         %s,          %s)
    """, ("descarte", id_agregado, None, 1, current_user.id,
          "Descartado via tela Itens do Tipo"), commit=True)

    flash("Agregado descartado e registrado no relatório.", "info")
    return redirect(_safe_next("listar_agregados_tipos"))

# ============================================================
# Ferramentas
# ============================================================
@app.route("/ferramentas")
@login_required
def listar_ferramentas():
    q      = request.args.get("q", "").strip()
    status = request.args.get("status", "").strip()

    where, params = [], []
    if q:
        where.append("(f.nome LIKE %s OR IFNULL(f.endereco_estoque,'') LIKE %s)")
        params += [f"%{q}%", f"%{q}%"]
    if status:
        where.append("f.status = %s")
        params.append(status)
    where_sql = (" WHERE " + " AND ".join(where)) if where else ""

    ferramentas = query(f"""
        SELECT id_ferramenta, nome, especial, endereco_estoque, status
        FROM ferramentas f
        {where_sql}
        ORDER BY nome
    """, params)

    resumo = query(f"""
        SELECT COUNT(*) total,
               SUM(status='Disponível') disp,
               SUM(status='Emprestada') emprestada,
               SUM(status='Calibração') calibracao,
               SUM(status='Descartada') descartada
        FROM ferramentas f
        {where_sql}
    """, params, fetchone=True) or {}

    filtros = {"q": q, "status": status}
    return render_template("ferramentas.html",
                           ferramentas=ferramentas, filtros=filtros, resumo=resumo)

@app.route("/ferramentas/excel")
@login_required
def exportar_ferramentas_excel():
    q      = request.args.get("q", "").strip()
    status = request.args.get("status", "").strip()

    where, params = [], []
    if q:
        where.append("(f.nome LIKE %s OR IFNULL(f.endereco_estoque,'') LIKE %s)")
        params += [f"%{q}%", f"%{q}%"]
    if status:
        where.append("f.status = %s")
        params.append(status)
    where_sql = (" WHERE " + " AND ".join(where)) if where else ""

    rows = query(f"""
        SELECT id_ferramenta, nome,
               IF(especial=1,'Sim','Não') AS especial,
               endereco_estoque, status
        FROM ferramentas f
        {where_sql}
        ORDER BY nome
    """, params)

    return make_excel_response(rows, "ferramentas.xlsx", sheet_name="Ferramentas")

@app.route("/ferramentas/novo", methods=["GET", "POST"])
@login_required
@admin_required
def nova_ferramenta():
    if request.method == "POST":
        query("""
            INSERT INTO ferramentas (nome,especial,endereco_estoque,status,estoque_min,estoque_max)
            VALUES (%s,%s,%s,%s,%s,%s)
        """, (
            request.form["nome"],
            1 if "especial" in request.form else 0,
            request.form.get("endereco_estoque"),
            request.form.get("status", "Disponível"),
            request.form.get("estoque_min", 0),
            request.form.get("estoque_max", 9999),
        ), commit=True)
        flash("Ferramenta criada!", "success")
        return redirect(url_for("listar_ferramentas"))

    return render_template("nova_ferramenta.html")

@app.route("/ferramentas/editar/<int:id_ferramenta>", methods=["GET", "POST"])
@login_required
@admin_required
def editar_ferramenta(id_ferramenta):
    ferramenta = query("SELECT * FROM ferramentas WHERE id_ferramenta=%s", (id_ferramenta,), fetchone=True)
    if not ferramenta:
        flash("Ferramenta não encontrada.", "warning")
        return redirect(url_for("listar_ferramentas"))

    if request.method == "POST":
        query("""
            UPDATE ferramentas
               SET nome=%s,
                   especial=%s,
                   endereco_estoque=%s,
                   status=%s,
                   estoque_min=%s,
                   estoque_max=%s
             WHERE id_ferramenta=%s
        """, (
            request.form["nome"],
            1 if "especial" in request.form else 0,
            request.form.get("endereco_estoque"),
            request.form.get("status", "Disponível"),
            request.form.get("estoque_min", 0),
            request.form.get("estoque_max", 9999),
            id_ferramenta
        ), commit=True)
        flash("Ferramenta atualizada!", "success")
        return redirect(url_for("listar_ferramentas"))

    return render_template("editar_ferramenta.html", ferramenta=ferramenta)

@app.route("/ferramentas/descartar/<int:id_ferramenta>")
@login_required
@admin_required
def descartar_ferramenta(id_ferramenta):
    query("UPDATE ferramentas SET status='Descartada' WHERE id_ferramenta=%s", (id_ferramenta,), commit=True)
    flash("Ferramenta descartada.", "info")
    return redirect(url_for("listar_ferramentas"))

# ============================================================
# Movimentações
# ============================================================
@app.route("/movimentacoes", methods=["GET", "POST"], endpoint="listar_movimentacoes")
@login_required
def listar_movimentacoes():
    # reaproveita o relatório
    return relatorio_movimentacoes()

@app.route("/movimentacoes/nova", methods=["GET", "POST"])
@login_required
def nova_movimentacao():
    v = request.values
    id_agregado   = v.get("id_agregado")
    id_ferramenta = v.get("id_ferramenta")
    is_tool = (v.get("is_tool") == "1") or (id_ferramenta and not id_agregado)

    tipo = (v.get("tipo") or "").strip()
    if request.method == "GET":
        if is_tool:
            if tipo not in ("emprestimo", "devolucao_ferramenta", "devolucao"):
                tipo = "emprestimo"
            if tipo == "devolucao":
                tipo = "devolucao_ferramenta"
        else:
            if tipo not in ("saida", "devolucao", "reforma"):
                tipo = "saida"

    # -------- listas para selects --------
    aplicado_em_prefill = None
    if not is_tool:
        status_filtro = "Disponível"
        if tipo == "devolucao":
            status_filtro = "Aplicado"

        agregados_disp = query("""
            SELECT id_agregado, CONCAT(tag,' - ',nome) AS nome
            FROM agregados
            WHERE status=%s
            ORDER BY nome
        """, (status_filtro,))

        # Prefill do "Aplicado em" quando estamos em DEVOLUÇÃO
        if tipo == "devolucao" and id_agregado:
            r = query("SELECT aplicado_em FROM agregados WHERE id_agregado=%s",
                      (id_agregado,), fetchone=True)
            aplicado_em_prefill = (r or {}).get("aplicado_em")
    else:
        agregados_disp = []

    # Ferramentas
    ferramentas = []
    if is_tool:
        if tipo == "emprestimo":
            ferramentas = query("""
                SELECT id_ferramenta, nome
                FROM ferramentas
                WHERE status='Disponível'
                ORDER BY nome
            """)
        else:
            ferramentas = query("""
                SELECT id_ferramenta, nome
                FROM ferramentas
                WHERE status='Emprestada'
                ORDER BY nome
            """)

    if request.method == "POST":
        tipo_in = (request.form.get("tipo") or "").strip()
        if is_tool and tipo_in in ("devolucao", "devolucao_ferramenta"):
            tipo_in = "devolucao_ferramenta"

        id_agregado   = request.form.get("id_agregado") or None
        id_ferramenta = request.form.get("id_ferramenta") or None
        observacao    = request.form.get("observacao") or None

        # Agregados
        quantidade  = int(request.form.get("quantidade", 1))
        aplicado_em = request.form.get("aplicado_em") or None

        # Ferramentas
        emprestado_para = request.form.get("emprestado_para") or None
        matricula       = request.form.get("matricula") or None

        # Validações (ferramentas)
        if id_ferramenta:
            if tipo_in == "emprestimo":
                if not emprestado_para or not matricula:
                    flash("Informe 'Emprestado para' e 'Matrícula' para o empréstimo.", "warning")
                    return redirect(request.url)
                f = query("SELECT status FROM ferramentas WHERE id_ferramenta=%s",
                          (id_ferramenta,), fetchone=True)
                if not f or f["status"] != "Disponível":
                    st = f["status"] if f else "indisponível"
                    flash(f"A ferramenta selecionada está com status '{st}'.", "danger")
                    return redirect(request.url)
            elif tipo_in == "devolucao_ferramenta":
                f = query("SELECT status FROM ferramentas WHERE id_ferramenta=%s",
                          (id_ferramenta,), fetchone=True)
                if not f or f["status"] != "Emprestada":
                    flash("Esta ferramenta não está marcada como 'Emprestada'.", "danger")
                    return redirect(request.url)

        # Registra movimentação
        query("""
            INSERT INTO movimentacoes
                (tipo, id_agregado, id_ferramenta, quantidade, id_usuario,
                 observacao, emprestado_para, matricula)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (tipo_in, id_agregado, id_ferramenta, quantidade, current_user.id,
              observacao, emprestado_para, matricula), commit=True)

        # Atualiza estoque (agregados)
        if id_agregado:
            if tipo_in == "saida":
                query("""
                    UPDATE agregados
                       SET status='Aplicado', aplicado_em=%s
                     WHERE id_agregado=%s AND status='Disponível'
                """, (aplicado_em, id_agregado), commit=True)
            elif tipo_in == "devolucao":
                query("""
                    UPDATE agregados
                       SET status='Disponível', aplicado_em=NULL
                     WHERE id_agregado=%s
                """, (id_agregado,), commit=True)
            elif tipo_in == "reforma":
                query("UPDATE agregados SET status='Em reforma' WHERE id_agregado=%s",
                      (id_agregado,), commit=True)

        # Atualiza estoque (ferramentas)
        if id_ferramenta:
            if tipo_in == "emprestimo":
                query("UPDATE ferramentas SET status='Emprestada' WHERE id_ferramenta=%s",
                      (id_ferramenta,), commit=True)
            elif tipo_in == "devolucao_ferramenta":
                query("UPDATE ferramentas SET status='Disponível' WHERE id_ferramenta=%s",
                      (id_ferramenta,), commit=True)

        flash("Movimentação registrada!", "success")
        return redirect(url_for("listar_movimentacoes"))

    return render_template(
        "nova_movimentacao.html",
        tipo=tipo,
        is_tool=is_tool,
        agregados=agregados_disp,
        ferramentas=ferramentas,
        id_agregado=id_agregado or "",
        id_ferramenta=id_ferramenta or "",
        g_nome=request.args.get("g_nome"),
        g_aplicacao=request.args.get("g_aplicacao"),
        aplicado_em_prefill=aplicado_em_prefill,
    )

@app.get("/api/agregados/<int:id_agregado>/aplicado-em")
@login_required
def api_agregado_aplicado_em(id_agregado):
    """Retorna o 'aplicado_em' atual do agregado (JSON)."""
    r = query("SELECT aplicado_em FROM agregados WHERE id_agregado=%s",
              (id_agregado,), fetchone=True)
    return jsonify({"aplicado_em": (r or {}).get("aplicado_em") or ""})

# ============================================================
# Relatórios — lista + Excel
# ============================================================
@app.route("/relatorios/movimentacoes", methods=["GET", "POST"])
@login_required
def relatorio_movimentacoes():
    base = """
        SELECT m.id_mov, m.tipo, m.quantidade, m.data_mov, m.observacao,
               m.emprestado_para, m.matricula,
               u.nome AS usuario,
               CONCAT(a.tag,' - ',a.nome) AS agregado,
               CONCAT(f.id_ferramenta,' - ',f.nome) AS ferramenta
        FROM movimentacoes m
        LEFT JOIN usuarios u    ON m.id_usuario=u.id_usuario
        LEFT JOIN agregados a   ON m.id_agregado=a.id_agregado
        LEFT JOIN ferramentas f ON m.id_ferramenta=f.id_ferramenta
        WHERE 1=1
    """
    params = []
    v = request.values

    data_inicio = v.get("data_inicio")
    data_fim    = v.get("data_fim")
    if data_inicio and data_fim:
        base += " AND DATE(m.data_mov) BETWEEN %s AND %s"
        params += [data_inicio, data_fim]

    tipo = (v.get("tipo") or "").strip()
    if tipo:
        base += " AND m.tipo=%s"
        params.append(tipo)

    for campo in ["id_agregado", "id_ferramenta", "id_usuario"]:
        val = v.get(campo)
        if val:
            base += f" AND m.{campo}=%s"
            params.append(val)

    emp_para = (v.get("emprestado_para") or "").strip()
    if emp_para:
        base += " AND m.emprestado_para LIKE %s"
        params.append(f"%{emp_para}%")

    matricula = (v.get("matricula") or "").strip()
    if matricula:
        base += " AND m.matricula LIKE %s"
        params.append(f"%{matricula}%")

    base += " ORDER BY m.data_mov DESC"
    movimentacoes = query(base, params)

    agregados   = query("SELECT id_agregado, CONCAT(tag,' - ',nome) AS nome FROM agregados ORDER BY nome")
    ferramentas = query("SELECT id_ferramenta, nome FROM ferramentas ORDER BY nome")
    usuarios    = query("SELECT id_usuario, nome FROM usuarios ORDER BY nome")

    return render_template(
        "relatorio_movimentacoes.html",
        movimentacoes=movimentacoes,
        agregados=agregados,
        ferramentas=ferramentas,
        usuarios=usuarios,
    )

@app.route("/relatorios/movimentacoes/excel", methods=["GET", "POST"])
@login_required
def exportar_movimentacoes_excel():
    """Exporta exatamente o que está filtrado no relatório (GET ou POST)."""
    base = """
        SELECT m.id_mov            AS ID,
               DATE_FORMAT(m.data_mov,'%%d/%%m/%%Y %%H:%%i') AS Data,
               m.tipo             AS Tipo,
               u.nome             AS Usuario,
               CONCAT(a.tag,' - ',a.nome) AS Agregado,
               CONCAT(f.id_ferramenta,' - ',f.nome) AS Ferramenta,
               m.emprestado_para  AS Emprestado_para,
               m.matricula        AS Matricula,
               m.quantidade       AS Quantidade,
               m.observacao       AS Observacao
        FROM movimentacoes m
        LEFT JOIN usuarios u    ON m.id_usuario=u.id_usuario
        LEFT JOIN agregados a   ON m.id_agregado=a.id_agregado
        LEFT JOIN ferramentas f ON m.id_ferramenta=f.id_ferramenta
        WHERE 1=1
    """
    params = []
    v = request.values  # aceita GET e POST

    data_inicio = v.get("data_inicio")
    data_fim    = v.get("data_fim")
    if data_inicio and data_fim:
        base += " AND DATE(m.data_mov) BETWEEN %s AND %s"
        params += [data_inicio, data_fim]

    tipo = (v.get("tipo") or "").strip()
    if tipo:
        base += " AND m.tipo=%s"
        params.append(tipo)

    for campo in ["id_agregado", "id_ferramenta", "id_usuario"]:
        val = v.get(campo)
        if val:
            base += f" AND m.{campo}=%s"
            params.append(val)

    emp_para = (v.get("emprestado_para") or "").strip()
    if emp_para:
        base += " AND m.emprestado_para LIKE %s"
        params.append(f"%{emp_para}%")

    matricula = (v.get("matricula") or "").strip()
    if matricula:
        base += " AND m.matricula LIKE %s"
        params.append(f"%{matricula}%")

    base += " ORDER BY m.data_mov DESC"
    rows = query(base, params)

    # Gera Excel
    output = io.BytesIO()
    df = pd.DataFrame(rows or [])
    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name="Movimentações")
    output.seek(0)

    return send_file(
        output,
        as_attachment=True,
        download_name="relatorio_movimentacoes.xlsx",
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )

# ============================================================
# Relatório: Baixa Rotatividade (Agregados)
# ============================================================
@app.route("/relatorios/baixa-rotatividade")
@login_required
def baixa_rotatividade():
    """
    Lista agregados com baixa rotatividade:
    - última movimentação há >= 'dias' (padrão 60), OU nunca movimentados.
    Aceita busca rápida por TAG / nome / aplicação (q).
    """
    try:
        dias = int(request.args.get("dias", 60))
    except Exception:
        dias = 60

    q = (request.args.get("q") or "").strip()

    base = f"""
        SELECT
            a.id_agregado,
            a.tag,
            a.nome,
            a.aplicacao,
            a.status,
            a.localizacao,
            a.aplicado_em,
            MAX(m.data_mov)                                     AS ultima_mov_dt,
            DATE_FORMAT(MAX(m.data_mov),'%%d/%%m/%%Y %%H:%%i')  AS ultima_mov_fmt,
            CASE
              WHEN MAX(m.data_mov) IS NULL THEN NULL
              ELSE DATEDIFF(CURDATE(), MAX(m.data_mov))
            END AS dias_sem_mov
        FROM agregados a
        LEFT JOIN movimentacoes m
               ON m.id_agregado = a.id_agregado
        { "WHERE (a.tag LIKE %s OR a.nome LIKE %s OR IFNULL(a.aplicacao,'') LIKE %s)" if q else "" }
        GROUP BY a.id_agregado, a.tag, a.nome, a.aplicacao, a.status, a.localizacao, a.aplicado_em
        HAVING (ultima_mov_dt IS NULL OR dias_sem_mov >= %s)
        ORDER BY
            CASE WHEN ultima_mov_dt IS NULL THEN 0 ELSE 1 END ASC,
            dias_sem_mov DESC
    """

    params = []
    if q:
        like = f"%{q}%"
        params += [like, like, like]
    params.append(dias)

    rows = query(base, params)

    return render_template("baixa_rotatividade.html", rows=rows, dias=dias, q=q)

@app.route("/relatorios/baixa-rotatividade/excel")
@login_required
def baixa_rotatividade_excel():
    """Exporta a mesma lista para Excel."""
    try:
        dias = int(request.args.get("dias", 60))
    except Exception:
        dias = 60

    q = (request.args.get("q") or "").strip()

    base = f"""
        SELECT
            a.tag                AS TAG,
            a.nome               AS Descricao,
            a.aplicacao          AS Aplicacao,
            a.status             AS Status,
            a.localizacao        AS Localizacao,
            a.aplicado_em        AS Aplicado_em,
            DATE_FORMAT(MAX(m.data_mov),'%%d/%%m/%%Y %%H:%%i') AS Ultima_mov,
            CASE
              WHEN MAX(m.data_mov) IS NULL THEN NULL
              ELSE DATEDIFF(CURDATE(), MAX(m.data_mov))
            END AS Dias_sem_mov
        FROM agregados a
        LEFT JOIN movimentacoes m
               ON m.id_agregado = a.id_agregado
        { "WHERE (a.tag LIKE %s OR a.nome LIKE %s OR IFNULL(a.aplicacao,'') LIKE %s)" if q else "" }
        GROUP BY a.id_agregado, a.tag, a.nome, a.aplicacao, a.status, a.localizacao, a.aplicado_em
        HAVING (MAX(m.data_mov) IS NULL OR DATEDIFF(CURDATE(), MAX(m.data_mov)) >= %s)
        ORDER BY
            CASE WHEN MAX(m.data_mov) IS NULL THEN 0 ELSE 1 END ASC,
            DATEDIFF(CURDATE(), MAX(m.data_mov)) DESC
    """

    params = []
    if q:
        like = f"%{q}%"
        params += [like, like, like]
    params.append(dias)

    rows = query(base, params)
    return make_excel_response(rows, f"baixa_rotatividade_{dias}d.xlsx", sheet_name="Baixa Rotatividade")

# ============================================================
# Inicialização
# ============================================================
if __name__ == "__main__":
    app.run(debug=True)