from flask import Flask, render_template, request, session, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import os
import psycopg2
from psycopg2 import errors

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")


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

        cursor.close()
        conexao.close()

        if usuario and check_password_hash(usuario[3], senha):
            session["usuario"] = usuario[2]
            return redirect(url_for("home"))

        return render_template("login.html", erro="E-mail ou senha incorretos")

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

    cursor.close()
    conexao.close()

    if usuario:
        nome = usuario[0]
        return render_template("home.html", nome=nome)

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

        conexao.commit()

        cursor.close()
        conexao.close()

        return render_template(
            "seguranca.html",
            sucesso="Senha alterada com sucesso!"
        )

    return render_template("seguranca.html")

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

    session.pop("usuario", None)

    return redirect(url_for("inicio"))


if __name__ == "__main__":
    app.run(debug=True)

