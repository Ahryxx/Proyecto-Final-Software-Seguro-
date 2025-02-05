import bcrypt
import jwt
import datetime
import secrets
import smtplib
from functools import wraps
from flask import Flask, request, jsonify, render_template
import psycopg2
from psycopg2.extras import RealDictCursor
import requests
from config import SECRET_KEY,SMTP_PORT,SMTP_SERVER,EMAIL_ADDRESS,EMAIL_PASSWORD
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.backends import default_backend
from apscheduler.schedulers.background import BackgroundScheduler
import os
import base64

app = Flask(__name__)


# Conexión a la base de datos principal (usuarios)
def get_db_connection():
    try:
        conn = psycopg2.connect(
            "postgresql://postgres:npg_H9UzaGen3Zfg@ep-dark-resonance-a2kztjpx-pooler.eu-central-1.aws.neon.tech/secure?sslmode=require"
        )
        print("Conexión a la base de datos establecida correctamente.")
        return conn
    except Exception as e:
        print("Error al conectar con la base de datos:", e)
        return None

# Conexión a la base de datos de auditoría
def get_audit_db_connection():
    try:
        conn = psycopg2.connect(
            "postgresql://postgres:npg_H9UzaGen3Zfg@ep-dark-resonance-a2kztjpx-pooler.eu-central-1.aws.neon.tech/auditoria?sslmode=require"
        )
        print("Conexión a la base de datos establecida correctamente.")
        return conn
    except Exception as e:
        print("Error al conectar con la base de datos:", e)
        return None

# Decorador para verificar roles
def requires_role(role):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            token = request.headers.get('Authorization')
            if not token:
                return jsonify({"error": "Token no proporcionado"}), 401

            try:
                # Verifica si el token comienza con "Bearer "
                if not token.startswith("Bearer "):
                    return jsonify({"error": "Formato de token inválido"}), 401

                # Extrae el token sin "Bearer "
                token = token.split(" ")[1]

                # Decodifica el token
                payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
                print("Payload decodificado:", payload)  # Log para depuración

                # Imprimir el tiempo restante del token
                expiration_time = datetime.datetime.fromtimestamp(payload['exp'], tz=datetime.timezone.utc)
                current_time = datetime.datetime.now(datetime.timezone.utc)
                time_remaining = expiration_time - current_time
                print(f"Tiempo restante del token: {time_remaining}")  # Log para depuración

                # Verifica el rol
                if payload.get('role') != role:
                    return jsonify({"error": "Acceso no autorizado"}), 403

                return func(*args, **kwargs)

            except jwt.ExpiredSignatureError:
                return jsonify({"error": "Token expirado"}), 401
            except jwt.InvalidTokenError as e:
                print("Error decodificando el token:", e)  # Log para depuración
                return jsonify({"error": "Token inválido"}), 401

        return wrapper
    return decorator


@app.route("/eliminar_expirados", methods=["GET"])
def ejecutar_eliminar_expirados():
    eliminar_usuarios_expirados()
    return "Usuarios expirados procesados correctamente.", 200

# Función para enviar correo electrónico
def send_email(to_email, subject, body):
    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        
        # Codificar el cuerpo del correo en UTF-8
        message = f"Subject: {subject}\n\n{body}".encode('utf-8')
        
        server.sendmail(EMAIL_ADDRESS, to_email, message)
        server.quit()
        return True
    except Exception as e:
        print(f"Error enviando correo: {e}")
        return False
    

scheduler = BackgroundScheduler()

# Función que se ejecutará periódicamente
def eliminar_usuarios_expirados():
    try:
        conn = get_db_connection()
        if conn is None:
            print("No se pudo conectar a la base de datos")
            return

        cur = conn.cursor()

        # Obtener nombres de columnas excepto 'user_id' e 'id'
        cur.execute("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'usuarios' AND column_name NOT IN ('user_id', 'id');
        """)
        columnas = [row[0] for row in cur.fetchall()]
        
        if not columnas:
            print("No hay columnas para limpiar.")
            return
        
        # Crear la consulta UPDATE dinámica
        update_query = f"""
            UPDATE usuarios 
            SET {", ".join(f"{col} = NULL" for col in columnas)}
            WHERE fecha_expiracion IS NOT NULL AND fecha_expiracion < %s;
        """
        
        cur.execute(update_query, (datetime.datetime.now(),))
        conn.commit()
        
        print(f"Usuarios expirados han sido limpiados.")

        cur.close()
        conn.close()

    except Exception as e:
        print(f"Error al limpiar usuarios expirados: {e}")

# Programar la tarea para que se ejecute cada 24 horas (puedes ajustar la frecuencia)
scheduler.add_job(eliminar_usuarios_expirados, 'interval', hours=24)

# Iniciar el programador
scheduler.start()


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        # Renderizar la plantilla de inicio de sesión
        return render_template('login.html')

    # Si es una solicitud POST, procesar el inicio de sesión
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Credenciales requeridas"}), 400

    try:
        # Conectar a la base de datos principal
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)

        # Buscar al usuario en la base de datos
        cur.execute("SELECT * FROM login WHERE username = %s", (username,))
        user = cur.fetchone()

        # Verificar si el usuario existe y si la contraseña es correcta
        if not user or not bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
            # Registrar el intento fallido en la base de datos de auditoría
            audit_conn = get_audit_db_connection()
            audit_cur = audit_conn.cursor()
            audit_cur.execute(
                "INSERT INTO audit_logs (user_id, action, details) VALUES (%s, %s, %s)",
                (None, 'login_fallido', f"Intento fallido para: {username} desde IP: {request.remote_addr}")
            )
            audit_conn.commit()
            audit_cur.close()
            audit_conn.close()

            # Devolver un error si las credenciales son inválidas
            return jsonify({"error": "Credenciales inválidas"}), 401

        # Verificar si el correo electrónico del usuario está verificado
        if not user['verified']:
            return jsonify({"error": "Por favor, verifica tu correo electrónico antes de iniciar sesión"}), 401

        # Generar un token JWT para el usuario
        token = jwt.encode({
            'username': user['username'],
            'user_id': user['id'],  # Added user_id
            'role': user['role'],
            'exp': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
        }, SECRET_KEY, algorithm='HS256')

        print("Token generado:", token)  # Log para depuración

        # Registrar el inicio de sesión exitoso en la base de datos de auditoría
        audit_conn = get_audit_db_connection()
        audit_cur = audit_conn.cursor()
        audit_cur.execute(
            "INSERT INTO audit_logs (user_id, action, details) VALUES (%s, %s, %s)",
            (user['id'], 'login_exitoso', f"Login desde IP: {request.remote_addr}")
        )
        audit_conn.commit()

        # Cerrar conexiones a las bases de datos
        audit_cur.close()
        audit_conn.close()
        cur.close()
        conn.close()

        # Si el rol es 'admin', redirigir a localhost:5001/usuarios/resumen
        if user['role'] == 'admin':
            return jsonify({
                'token': token,
                'user_id': user['id'],
                'redirect_url': 'http://localhost:5001/usuarios/resumen'
            }), 200
        else:
            # Devolver el token y el ID del usuario en la respuesta
            return jsonify({'token': token, 'user_id': user['id']}), 200

    except Exception as e:
        # Manejar cualquier error que ocurra durante el proceso
        return jsonify({"error": str(e)}), 500
    

# Función para generar una clave única usando el user_id del usuario
def generar_clave(user_id):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(str(user_id).encode('utf-8'))
    clave = digest.finalize()
    return clave

# Función para encriptar datos
def encriptar(datos, clave):
    iv = os.urandom(16)
    cifrador = Cipher(algorithms.AES(clave), modes.GCM(iv), backend=default_backend()).encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    datos_padded = padder.update(datos.encode('utf-8')) + padder.finalize()
    datos_encriptados = cifrador.update(datos_padded) + cifrador.finalize()
    resultado = base64.b64encode(iv + cifrador.tag + datos_encriptados).decode('utf-8')
    return resultado

# Modificar el endpoint /register para encriptar los datos antes de almacenarlos
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('registro.html')

    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')
    role = data.get('role', 'cliente')

    if not username or not password or not email:
        return jsonify({"error": "Usuario, contraseña y correo electrónico requeridos"}), 400

    try:
        # Generar el hash de la contraseña
        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        # Conexión a la base de datos principal
        conn = get_db_connection()
        cur = conn.cursor()

        # Verificar si el usuario ya existe
        cur.execute("SELECT id FROM login WHERE username = %s", (username,))
        if cur.fetchone():
            return jsonify({"error": "El nombre de usuario ya existe"}), 400

        # Insertar el nuevo usuario en la tabla login
        cur.execute(
            "INSERT INTO login (username, password_hash, email, role, verified) VALUES (%s, %s, %s, %s, %s) RETURNING id",
            (username, hashed_pw, email, role, False)
        )
        user_id = cur.fetchone()[0]
        conn.commit()

        # Generar la clave única para el usuario
        clave = generar_clave(user_id)

        # Encriptar los datos sensibles
        nombre_encriptado = encriptar(username, clave)
        correo_encriptado = encriptar(email, clave)

        # Insertar en la tabla usuarios con los datos encriptados
        cur.execute(
            "INSERT INTO usuarios (user_id, nombre, correo) VALUES (%s, %s, %s)",
            (user_id, nombre_encriptado, correo_encriptado)
        )
        conn.commit()

        # Generar token de verificación
        verification_token = secrets.token_hex(16)
        cur.execute(
            "INSERT INTO verification_tokens (user_id, token) VALUES (%s, %s)",
            (user_id, verification_token)
        )
        conn.commit()

        # Enviar correo electrónico con el token de verificación
        subject = "Verificación de correo electrónico"
        body = f"Por favor, utiliza el siguiente token para verificar tu correo electrónico: {verification_token}"
        if not send_email(email, subject, body):
            return jsonify({"error": "Error enviando el correo de verificación"}), 500

        # Registrar la acción en la base de datos de auditoría
        audit_conn = get_audit_db_connection()
        audit_cur = audit_conn.cursor()
        audit_cur.execute(
            "INSERT INTO audit_logs (user_id, action, details) VALUES (%s, %s, %s)",
            (user_id, 'registro', f'Registro exitoso para {username}')
        )
        audit_conn.commit()

        # Cerrar conexiones
        audit_cur.close()
        audit_conn.close()
        cur.close()
        conn.close()

        # Devolver una respuesta exitosa
        return jsonify({"message": "Registro exitoso. Por favor, verifica tu correo electrónico."}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

    
@app.route('/verify', methods=['GET', 'POST'])
def verify_email():
    if request.method == 'GET':
        # Si es una solicitud GET, renderizamos la plantilla de verificación.
        return render_template('verify.html')
    
    elif request.method == 'POST':
        # Procesamos la verificación del token enviado en el cuerpo de la solicitud (JSON).
        data = request.get_json()
        token = data.get('token')

        if not token:
            return jsonify({"error": "Token de verificación requerido"}), 400

        try:
            conn = get_db_connection()
            cur = conn.cursor()

            # Buscar el token en la base de datos
            cur.execute("SELECT user_id FROM verification_tokens WHERE token = %s", (token,))
            result = cur.fetchone()

            if not result:
                return jsonify({"error": "Token inválido"}), 400

            user_id = result[0]

            # Marcar al usuario como verificado
            cur.execute("UPDATE login SET verified = TRUE WHERE id = %s", (user_id,))
            conn.commit()

            # Eliminar el token de verificación
            cur.execute("DELETE FROM verification_tokens WHERE token = %s", (token,))
            conn.commit()

            # Registrar la acción en la base de datos de auditoría
            audit_conn = get_audit_db_connection()
            audit_cur = audit_conn.cursor()
            audit_cur.execute(
                "INSERT INTO audit_logs (user_id, action, details) VALUES (%s, %s, %s)",
                (user_id, 'verificacion', 'Correo electrónico verificado')
            )
            audit_conn.commit()

            # Cerrar conexiones
            audit_cur.close()
            audit_conn.close()
            cur.close()
            conn.close()

            return jsonify({"message": "Correo electrónico verificado exitosamente"}), 200

        except Exception as e:
            return jsonify({"error": str(e)}), 500


# Ruta protegida para admin
@app.route('/admin', methods=['GET'])
@requires_role('admin')
def admin_dashboard():
    return jsonify({"message": "Panel de Administrador"}), 200

# Ruta protegida para cliente
@app.route('/cliente/info', methods=['GET'])
@requires_role('cliente')
def get_cliente_info():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({"error": "Token no proporcionado"}), 401

    try:
        # Extraer el token sin "Bearer "
        token = token.split(" ")[1]

        # Decodificar el token para obtener el nombre de usuario
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        username = payload.get('username')

        # Obtener el ID del cliente desde la base de datos principal
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT id FROM login WHERE username = %s", (username,))
        user = cur.fetchone()
        cur.close()
        conn.close()

        if not user:
            return jsonify({"error": "Usuario no encontrado"}), 404

        user_id = user['id']

        # Hacer una solicitud a la segunda API para obtener la información del cliente
        segunda_api_url = f"http://localhost:5001/usuarios/{user_id}"  # Cambia el puerto si es necesario
        response = requests.get(segunda_api_url)

        if response.status_code != 200:
            return jsonify({"error": "Error al obtener la información del cliente"}), response.status_code

        # Retornar la información del cliente
        return jsonify(response.json()), 200

    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expirado"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Token inválido"}), 401
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)  # Cambia el puerto si es necesario