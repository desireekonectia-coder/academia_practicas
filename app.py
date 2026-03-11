from flask import Flask, render_template, request, redirect, url_for, session
from functools import wraps
import psycopg2
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import os

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "clave_segura_123")

def conectar_bd():
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

# Función auxiliar para redirigir según el rol y evitar repetir código
def redirigir_segun_rol(rol):
    if rol == 'admin':
        return redirect(url_for('panel_admin'))
    elif rol == 'profesor':
        return redirect(url_for('panel_profesor'))
    return "Rol no reconocido"

@app.route("/", methods=["GET", "POST"])
def login_registro():
    # SOLUCIÓN: Si ya hay sesión, redirigir al panel correcto (no a 'perfil')
    if 'usuario' in session:
        return redirigir_segun_rol(session.get('rol'))
    
    mensaje = ""
    if request.method == "POST":
        usuario_ingresado = request.form["username"]
        password_ingresada = request.form["password"]

        conn = conectar_bd()
        cursor = conn.cursor()
        
        cursor.execute("SELECT nombre, password_hash, rol FROM usuarios WHERE nombre=%s", (usuario_ingresado,))
        resultado = cursor.fetchone()

        if resultado:
            nombre_db, hash_guardado, rol_guardado = resultado
            
            if check_password_hash(hash_guardado, password_ingresada):
                session['usuario'] = nombre_db
                session['rol'] = rol_guardado
                
                cursor.close()
                conn.close()
                return redirigir_segun_rol(rol_guardado)
            else:
                mensaje = "Contraseña incorrecta."
        else:
            mensaje = "El usuario no existe."

        cursor.close()
        conn.close()
        
    return render_template("login.html", mensaje=mensaje)

@app.route("/admin")
@login_requerido
def panel_admin():
    if session.get('rol') != 'admin':
        return "Acceso denegado: No eres administrador", 403
    return render_template("admin_dashboard.html", nombre=session['usuario'])

@app.route("/profesor")
@login_requerido
def panel_profesor():
    if session.get('rol') != 'profesor':
        return "Acceso denegado: No eres profesor", 403
    return render_template("profesor_dashboard.html", nombre=session['usuario'])

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for('login_registro'))

if __name__ == "__main__":
    app.run(debug=True)