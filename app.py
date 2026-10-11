from flask import Flask, render_template, request, session, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from flask_wtf.csrf import CSRFProtect
import os
import psycopg2
from psycopg2 import errors

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False
)

csrf = CSRFProtect(app)

def conectar_banco():
    return psycopg2.connect(
        host=os.getenv("DB_HOST"),
        port=os.getenv("DB_PORT"),
        database=os.getenv("DB_NAME"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD")
    )

conexao = conectar_banco()
print("Conectado ao PostgreSQL!")
conexao.close()

@app.route("/", methods=["GET", "POST"])
def inicio():

    if request.method == "POST":

        email = request.form["email"]
        senha = request.form["senha"]

        conexao = conectar_banco()
        cursor = conexao.cursor()

        cursor.execute(
            "SELECT id, nome, email, senha FROM usuarios WHERE email = %s",
            (email,)
        )

        usuario = cursor.fetchone()

        if usuario and check_password_hash(usuario[3], senha):

            session["usuario"] = usuario[2]

            cursor.execute(
                """
                INSERT INTO atividades (usuario_id, descricao, tipo)
                VALUES (%s, %s, %s)
                """,
                (usuario[0], "Login realizado", "login")
            )

            conexao.commit()

            cursor.close()
            conexao.close()

            return redirect(url_for("home"))

        cursor.close()
        conexao.close()

        return render_template(
            "login.html",
            erro="E-mail ou senha incorretos"
        )

    return render_template("login.html")

@app.route("/cadastro", methods=["GET", "POST"])
def cadastro():

    if request.method == "POST":

        nome = request.form["nome"].strip()
        email = request.form["email"].strip()
        senha = request.form["senha"]
        confirmar_senha = request.form["confirmar_senha"]

        if not nome:
            return render_template(
                "cadastro.html",
                erro="Digite seu nome!",
                nome=nome,
                email=email
            )

        if not email.strip():
            return render_template(
                "cadastro.html",
                erro="Digite seu e-mail!",
                nome=nome,
                email=email
            )

        if len(senha) < 8:
            return render_template(
                "cadastro.html",
                erro="A senha deve ter no mínimo 8 caracteres!",
                nome=nome,
                email=email
            )

        if senha != confirmar_senha:
            return render_template(
                "cadastro.html",
                erro="As senhas não coincidem!",
                nome=nome,
                email=email
            )

        senha_hash = generate_password_hash(senha)
        conexao = conectar_banco()
        cursor = conexao.cursor()

        try:
            cursor.execute(
                "INSERT INTO usuarios (nome, email, senha) VALUES (%s, %s, %s)",
                (nome, email, senha_hash)
            )

            conexao.commit()

        except errors.UniqueViolation:
            conexao.rollback()

            return render_template(
                "cadastro.html",
                erro="E-mail já cadastrado!",
                nome=nome,
                email=email
            )

        cursor.close()
        conexao.close()

        return "Cadastro realizado!"

    return render_template("cadastro.html")

@app.route("/home")
def home():

    if "usuario" not in session:
        return redirect(url_for("inicio"))

    conexao = conectar_banco()
    cursor = conexao.cursor()

    cursor.execute(
        "SELECT nome FROM usuarios WHERE email = %s",
        (session["usuario"],)
    )

    usuario = cursor.fetchone()

    cursor.execute(
        """
        SELECT descricao, data_atividade, tipo
        FROM atividades
        WHERE usuario_id = (
            SELECT id FROM usuarios WHERE email = %s
        )
        ORDER BY data_atividade DESC
        LIMIT 5
        """,
        (session["usuario"],)
    )

    atividades = cursor.fetchall()

    cursor.close()
    conexao.close()

    if usuario:
        nome = usuario[0]

        return render_template(
            "home.html",
            nome=nome,
            atividades=atividades
        )

    return redirect(url_for("inicio"))

@app.route("/perfil")
def perfil():

    if "usuario" not in session:
        return redirect(url_for("inicio"))

    conexao = conectar_banco()
    cursor = conexao.cursor()

    cursor.execute(
        "SELECT nome, email, data_criacao FROM usuarios WHERE email = %s",
        (session["usuario"],)
    )

    usuario = cursor.fetchone()

    cursor.close()
    conexao.close()

    if usuario:
        nome = usuario[0]
        email = usuario[1]
        data_criacao = usuario[2]

        return render_template(
            "perfil.html",
            nome=nome,
            email=email,
            data_criacao=data_criacao
        )

    return redirect(url_for("inicio"))

@app.route("/configuracoes")
def configuracoes():

    if "usuario" not in session:
        return redirect(url_for("inicio"))

    return render_template("configuracoes.html")

@app.route("/seguranca", methods=["GET", "POST"])
def seguranca():

    if "usuario" not in session:
        return redirect(url_for("inicio"))

    if request.method == "POST":

        senha_atual = request.form["senha_atual"]
        nova_senha = request.form["nova_senha"]
        confirmar_senha = request.form["confirmar_senha"]

        conexao = conectar_banco()
        cursor = conexao.cursor()

        cursor.execute(
            "SELECT senha FROM usuarios WHERE email = %s",
            (session["usuario"],)
        )

        usuario = cursor.fetchone()

        if not usuario or not check_password_hash(usuario[0], senha_atual):
            cursor.close()
            conexao.close()

            return render_template(
                "seguranca.html",
                erro="A senha atual está incorreta."
            )

        if len(nova_senha) < 8:
            cursor.close()
            conexao.close()

            return render_template(
                "seguranca.html",
                erro="A nova senha deve ter no mínimo 8 caracteres."
            )

        if nova_senha != confirmar_senha:
            cursor.close()
            conexao.close()

            return render_template(
                "seguranca.html",
                erro="As senhas não coincidem."
            )

        nova_senha_hash = generate_password_hash(nova_senha)

        cursor.execute(
            "UPDATE usuarios SET senha = %s WHERE email = %s",
            (nova_senha_hash, session["usuario"])
        )

        cursor.execute(
            """
            INSERT INTO atividades (usuario_id, descricao, tipo)
            SELECT id, %s, %s
            FROM usuarios
            WHERE email = %s
            """,
            ("Senha alterada", "senha", session["usuario"])
        )

        conexao.commit()

        cursor.close()
        conexao.close()

        return render_template(
            "seguranca.html",
            sucesso="Senha alterada com sucesso!"
        )

    return render_template("seguranca.html")

@app.route("/notificacoes", methods=["GET", "POST"])
def notificacoes():

    if "usuario" not in session:
        return redirect(url_for("inicio"))

    conexao = conectar_banco()
    cursor = conexao.cursor()

    cursor.execute(
        "SELECT id FROM usuarios WHERE email = %s",
        (session["usuario"],)
    )

    usuario = cursor.fetchone()

    if not usuario:
        cursor.close()
        conexao.close()
        return redirect(url_for("inicio"))

    usuario_id = usuario[0]
    sucesso = None

    if request.method == "POST":

        sistema = "sistema" in request.form
        email = "email" in request.form
        novidades = "novidades" in request.form

        cursor.execute(
            """
            UPDATE notificacoes
            SET sistema = %s,
                email = %s,
                novidades = %s
            WHERE usuario_id = %s
            """,
            (sistema, email, novidades, usuario_id)
        )

        cursor.execute(
            """
            INSERT INTO atividades (usuario_id, descricao, tipo)
            VALUES (%s, %s, %s)
            """,
            (usuario_id, "Preferências de notificações alteradas", "notificacoes")
        )


        conexao.commit()
        sucesso = "Preferências salvas com sucesso!"

    cursor.execute(
        "SELECT sistema, email, novidades FROM notificacoes WHERE usuario_id = %s",
        (usuario_id,)
    )

    preferencias = cursor.fetchone()

    cursor.close()
    conexao.close()

    return render_template(
        "notificacoes.html",
        usuario_id=usuario_id,
        sistema=preferencias[0],
        email=preferencias[1],
        novidades=preferencias[2],
        sucesso=sucesso if request.method == "POST" else None
    )

@app.route("/conta", methods=["GET", "POST"])
def conta():

    if "usuario" not in session:
        return redirect(url_for("inicio"))

    conexao = conectar_banco()
    cursor = conexao.cursor()

    cursor.execute(
        "SELECT nome, email FROM usuarios WHERE email = %s",
        (session["usuario"],)
    )

    usuario = cursor.fetchone()

    if not usuario:
        cursor.close()
        conexao.close()
        return redirect(url_for("inicio"))

    nome = usuario[0]
    email = usuario[1]

    if request.method == "POST":

        novo_nome = request.form["novo_nome"].strip()

        if not novo_nome:
            cursor.close()
            conexao.close()

            return render_template(
                "conta.html",
                nome=nome,
                email=email,
                erro="Digite um nome."
            )

        cursor.execute(
            "UPDATE usuarios SET nome = %s WHERE email = %s",
            (novo_nome, email)
        )

        cursor.execute(
            """
            INSERT INTO atividades (usuario_id, descricao, tipo)
            SELECT id, %s, %s
            FROM usuarios
            WHERE email = %s
            """,
            ("Nome alterado", "nome", email)
        )

        conexao.commit()

        cursor.close()
        conexao.close()

        return render_template(
            "conta.html",
            nome=novo_nome,
            email=email,
            sucesso="Nome alterado com sucesso!"
        )

    cursor.close()
    conexao.close()

    return render_template(
        "conta.html",
        nome=nome,
        email=email
    )

@app.route("/logout")
def logout():

    if "usuario" not in session:
        return redirect(url_for("inicio"))

    conexao = conectar_banco()
    cursor = conexao.cursor()

    cursor.execute(
        """
        INSERT INTO atividades (usuario_id, descricao, tipo)
        SELECT id, %s, %s
        FROM usuarios
        WHERE email = %s
        """,
        ("Logout realizado", "logout", session["usuario"])
    )

    conexao.commit()

    cursor.close()
    conexao.close()

    session.clear()

    return redirect(url_for("inicio"))

if __name__ == "__main__":
    app.run(debug=True)