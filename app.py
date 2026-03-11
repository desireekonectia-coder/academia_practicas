from flask import Flask, render_template, request, redirect, url_for, session
from functools import wraps
import psycopg2
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import os
import calendar
from datetime import datetime

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "clave_segura_123")


def conectar_bd(): # Nombre simplificado
    return psycopg2.connect(
        host=os.getenv("DB_HOST"),
        port=os.getenv("DB_PORT"),
        database=os.getenv("DB_NAME"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD")
    )


def login_requerido(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'usuario' not in session:
            return redirect(url_for('login_registro'))
        return f(*args, **kwargs)
    return decorated_function

@app.route("/", methods=["GET", "POST"])
def login_registro():
    if 'usuario' in session:
        return redirect(url_for('perfil'))
    
    mensaje = ""
    if request.method == "POST":
        usuario_ingresado = request.form["username"]
        password_ingresada = request.form["password"]

        conn = conectar_bd()
        cursor = conn.cursor()
        
        # Corregido: Seleccionamos de la tabla 'usuarios' y pedimos las columnas exactas
        cursor.execute("SELECT nombre, password_hash, rol FROM usuarios WHERE nombre=%s", (usuario_ingresado,))
        resultado = cursor.fetchone()

        if resultado:
            # Corregido: Solo desempaquetamos las 3 columnas solicitadas
            nombre_db, hash_guardado, rol_guardado = resultado
            
            if check_password_hash(hash_guardado, password_ingresada):
                session['usuario'] = nombre_db
                session['rol'] = rol_guardado
                
                cursor.close()
                conn.close()
                return redirect(url_for('perfil'))
            else:
                mensaje = "Contraseña incorrecta."
        else:
            mensaje = "El usuario no existe."

        cursor.close()
        conn.close()
        
    return render_template("login.html", mensaje=mensaje)