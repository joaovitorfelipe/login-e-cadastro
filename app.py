from flask import Flask, render_template, request, session, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import os

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

usuarios = []


@app.route("/", methods=["GET", "POST"])
def inicio():

    if request.method == "POST":

        email = request.form["email"]
        senha = request.form["senha"]

        for usuario in usuarios:

            if usuario["email"] == email and check_password_hash(usuario["senha"], senha):
                session["usuario"] = email
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

        if not nome.strip():
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

        for usuario in usuarios:

            if usuario["email"] == email:
                return render_template(
                    "cadastro.html",
                    erro="E-mail já cadastrado!"
                )

        senha_hash = generate_password_hash(senha)

        usuarios.append({
            "nome": nome,
            "email": email,
            "senha": senha_hash
        })

        print(usuarios)

        return "Cadastro realizado!"

    return render_template("cadastro.html")

@app.route("/home")
def home():

    if "usuario" not in session:
        return redirect(url_for("inicio"))

    for usuario in usuarios:

        if usuario["email"] == session["usuario"]:
            nome = usuario["nome"]

            return render_template("home.html", nome=nome)

@app.route("/logout")
def logout():

    session.pop("usuario", None)

    return redirect(url_for("inicio"))


if __name__ == "__main__":
    app.run(debug=True)

