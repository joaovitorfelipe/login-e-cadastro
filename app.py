from flask import Flask, render_template, request, session, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from flask_wtf.csrf import CSRFProtect
import os
import psycopg2
from psycopg2 import errors
from functools import wraps
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

def gerar_token_recuperacao(email):
    serializer = URLSafeTimedSerializer(app.secret_key)

    conexao = conectar_banco()
    cursor = conexao.cursor()

    try:
        cursor.execute(
            "SELECT senha FROM usuarios WHERE email = %s",
            (email,)
        )
        usuario = cursor.fetchone()

        if not usuario:
            return None

        dados = {
            "email": email,
            "senha_hash": usuario[0]
        }

        return serializer.dumps(dados, salt="recuperacao-senha")

    finally:
        cursor.close()
        conexao.close()


def verificar_token_recuperacao(token):
    serializer = URLSafeTimedSerializer(app.secret_key)

    try:
        dados = serializer.loads(
            token,
            salt="recuperacao-senha",
            max_age=1800
        )

        email = dados["email"]
        senha_hash_token = dados["senha_hash"]

        conexao = conectar_banco()
        cursor = conexao.cursor()

        try:
            cursor.execute(
                "SELECT senha FROM usuarios WHERE email = %s",
                (email,)
            )
            usuario = cursor.fetchone()

            if usuario and usuario[0] == senha_hash_token:
                return email

            return None

        finally:
            cursor.close()
            conexao.close()

    except (BadSignature, SignatureExpired, KeyError, TypeError):
        return None

app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = os.getenv("MAIL_USERNAME")
app.config["MAIL_PASSWORD"] = os.getenv("MAIL_PASSWORD")
app.config["MAIL_DEFAULT_SENDER"] = os.getenv("MAIL_USERNAME")

mail = Mail(app)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False
)

csrf = CSRFProtect(app)

def login_obrigatorio(funcao):
    @wraps(funcao)
    def verificar_sessao(*args, **kwargs):

        if "usuario" not in session:
            return redirect(url_for("inicio"))

        return funcao(*args, **kwargs)

    return verificar_sessao

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

@app.route("/recuperar-senha", methods=["GET", "POST"])
def recuperar_senha():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()

        if not email:
            return "Informe seu e-mail.", 400

        conexao = None
        cursor = None

        try:
            conexao = conectar_banco()
            cursor = conexao.cursor()

            cursor.execute(
                "SELECT email FROM usuarios WHERE email = %s",
                (email,)
            ) 
            usuario = cursor.fetchone()

            if usuario:
                token = gerar_token_recuperacao(email)

                if not token:
                    return "Não foi possível gerar o link de recuperação.", 400

                link = url_for(
                    "redefinir_senha",
                    token=token,
                    _external=True
                ).replace("127.0.0.1", "192.168.0.88")

                mensagem = Message(
                    subject="Recuperação de senha - Meu Sistema",
                    recipients=[email],
                    body=(
                        "Olá!\n\n"
                        "Recebemos uma solicitação para redefinir sua senha.\n\n"
                        f"Acesse o link abaixo para criar uma nova senha:\n{link}\n\n"
                        "Este link expira em 30 minutos.\n"
                        "Se você não solicitou essa alteração, ignore este e-mail."
                    )
                )

                mail.send(mensagem)

            return (
                "Se o e-mail estiver cadastrado, "
                "você receberá as instruções de recuperação."
            )

        except Exception as erro:
            print("Erro na recuperação de senha:", erro)
            return "Não foi possível processar a solicitação agora.", 500

        finally:
            if cursor:
                cursor.close()
            if conexao:
                conexao.close()

    return render_template("recuperar_senha.html")

@app.route("/redefinir-senha/<token>", methods=["GET", "POST"])
def redefinir_senha(token):
    email = verificar_token_recuperacao(token)

    if not email:
        return "Link inválido ou expirado. Solicite uma nova recuperação.", 400

    if request.method == "POST":
        nova_senha = request.form.get("senha", "")
        confirmar_senha = request.form.get("confirmar_senha", "")

        if len(nova_senha) < 8:
            return render_template(
                "redefinir_senha.html",
                erro="A senha deve ter no mínimo 8 caracteres."
            )

        if nova_senha != confirmar_senha:
            return render_template(
                "redefinir_senha.html",
                erro="As senhas não coincidem."
            )

        conexao = conectar_banco()
        cursor = conexao.cursor()

        try:
            nova_senha_hash = generate_password_hash(nova_senha)

            cursor.execute(
                "UPDATE usuarios SET senha = %s WHERE email = %s",
                (nova_senha_hash, email)
            )

            if cursor.rowcount == 0:
                conexao.rollback()
                return "Não foi possível redefinir a senha.", 400

            cursor.execute(
                """
                INSERT INTO atividades (usuario_id, descricao, tipo)
                SELECT id, %s, %s
                FROM usuarios
                WHERE email = %s
                """,
                ("Senha redefinida por e-mail", "senha", email)
            )

            conexao.commit()

        except Exception:
            conexao.rollback()
            raise

        finally:
            cursor.close()
            conexao.close()

        return """
            <h1>Senha redefinida!</h1>
            <p>Sua senha foi alterada com sucesso.</p>
            <a href="/">Voltar para o login</a>
        """

    return render_template("redefinir_senha.html")

@app.route("/home")
@login_obrigatorio
def home():

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
@login_obrigatorio
def perfil():

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
@login_obrigatorio
def configuracoes():

    return render_template("configuracoes.html")

@app.route("/seguranca", methods=["GET", "POST"])
@login_obrigatorio
def seguranca():

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
@login_obrigatorio
def notificacoes():

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
@login_obrigatorio
def conta():

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


@app.route("/logout", methods=["POST"])
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

@app.route("/teste-email", methods=["GET", "POST"])
@login_obrigatorio
def teste_email():
    if request.method == "POST":
        destinatario = request.form.get("email", "").strip()

        if not destinatario:
            return "Informe um e-mail.", 400

        try:
            mensagem = Message(
                subject="Teste de e-mail - Meu Sistema",
                recipients=[destinatario],
                body="Funcionou! Nosso sistema Flask conseguiu enviar um e-mail."
            )

            mail.send(mensagem)
            return "E-mail enviado com sucesso! Confira sua caixa de entrada."

        except Exception as erro:
            print("Erro ao enviar e-mail:", erro)
            return "Não foi possível enviar. Confira o terminal."

    return render_template("teste_email.html")


@app.route("/excluir-conta", methods=["GET", "POST"])
@login_obrigatorio
def excluir_conta():

    if request.method == "POST":

        senha = request.form.get("senha", "")

        conexao = None
        cursor = None

        try:
            conexao = conectar_banco()
            cursor = conexao.cursor()

            cursor.execute(
                "SELECT id, senha FROM usuarios WHERE email = %s",
                (session["usuario"],)
            )

            usuario = cursor.fetchone()

            if not usuario or not check_password_hash(usuario[1], senha):
                return render_template(
                    "excluir_conta.html",
                    erro="A senha está incorreta."
                )

            usuario_id = usuario[0]

            cursor.execute(
                "DELETE FROM atividades WHERE usuario_id = %s",
                (usuario_id,)
            )

            cursor.execute(
                "DELETE FROM notificacoes WHERE usuario_id = %s",
                (usuario_id,)
            )

            cursor.execute(
                "DELETE FROM usuarios WHERE id = %s",
                (usuario_id,)
            )

            conexao.commit()

            session.clear()

            return redirect(url_for("inicio"))

        except Exception:
            if conexao:
                conexao.rollback()

            app.logger.exception("Erro ao excluir conta.")

            return render_template(
                "excluir_conta.html",
                erro="Não foi possível excluir a conta. Tente novamente."
            )

        finally:
            if cursor:
                cursor.close()

            if conexao:
                conexao.close()

    return render_template("excluir_conta.html")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)