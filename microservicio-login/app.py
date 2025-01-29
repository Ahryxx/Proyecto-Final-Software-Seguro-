import bcrypt
import jwt
import datetime
import secrets
import smtplib
from functools import wraps
from flask import Flask, request, jsonify
import psycopg2
from psycopg2.extras import RealDictCursor

app = Flask(__name__)

SECRET_KEY = 'mi_clave_secreta'  # Debería ser más seguro en producción
DB_HOST = 'localhost'
DB_NAME = 'secure'
DB_USER = 'postgres'
DB_PASSWORD = '#Nowherefast1'
DB_PORT = '5432'
AUDIT_DB_NAME = 'auditoria'

# Configuración del servidor de correo
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587
EMAIL_ADDRESS = 'josegabrielfuertes@gmail.com'
EMAIL_PASSWORD = 'sbhs dpmt xulh wytc'

# Conexión a la base de datos principal (usuarios)
def get_db_connection():
    return psycopg2.connect(
        host=DB_HOST,
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD,
        port=DB_PORT
    )

# Conexión a la base de datos de auditoría
def get_audit_db_connection():
    return psycopg2.connect(
        host=DB_HOST,
        database=AUDIT_DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD,
        port=DB_PORT
    )

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

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')
    role = data.get('role', 'cliente')

    if not username or not password or not email:
        return jsonify({"error": "Usuario, contraseña y correo electrónico requeridos"}), 400

    try:
        # Generar el hash de la contraseña
        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')  # Decodificar a str

        # Conexión a la base de datos principal
        conn = get_db_connection()
        cur = conn.cursor()

        # Verificar si el usuario ya existe
        cur.execute("SELECT id FROM login WHERE username = %s", (username,))
        if cur.fetchone():
            return jsonify({"error": "El nombre de usuario ya existe"}), 400

        # Insertar el nuevo usuario con estado no verificado
        cur.execute(
            "INSERT INTO login (username, password_hash, email, role, verified) VALUES (%s, %s, %s, %s, %s) RETURNING id",
            (username, hashed_pw, email, role, False)
        )
        user_id = cur.fetchone()[0]
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

        return jsonify({"message": "Usuario registrado exitosamente. Por favor, verifica tu correo electrónico."}), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Ruta para validar el token de verificación
@app.route('/verify', methods=['POST'])
def verify_email():
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

# Login de usuario
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Credenciales requeridas"}), 400

    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT * FROM login WHERE username = %s", (username,))
        user = cur.fetchone()
        
        # Verificar credenciales
        if not user or not bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
            # Auditoría de intento fallido
            audit_conn = get_audit_db_connection()
            audit_cur = audit_conn.cursor()
            audit_cur.execute(
                "INSERT INTO audit_logs (user_id, action, details) VALUES (%s, %s, %s)",
                (None, 'login_fallido', f"Intento fallido para: {username}")
            )
            audit_conn.commit()
            audit_cur.close()
            audit_conn.close()
            
            return jsonify({"error": "Credenciales inválidas"}), 401

        # Verificar si el correo electrónico está verificado
        if not user['verified']:
            return jsonify({"error": "Por favor, verifica tu correo electrónico antes de iniciar sesión"}), 401

        # Generar JWT
        token = jwt.encode({
            'username': user['username'],
            'role': user['role'],
            'exp': datetime.datetime.now(datetime.UTC) + datetime.timedelta(hours=1)
        }, SECRET_KEY, algorithm='HS256')

        print("Token generado:", token)

        # Auditoría de login exitoso
        audit_conn = get_audit_db_connection()
        audit_cur = audit_conn.cursor()
        audit_cur.execute(
            "INSERT INTO audit_logs (user_id, action, details) VALUES (%s, %s, %s)",
            (user['id'], 'login_exitoso', f"Login desde IP: {request.remote_addr}")
        )
        audit_conn.commit()
        
        # Cerrar conexiones
        audit_cur.close()
        audit_conn.close()
        cur.close()
        conn.close()
        
        return jsonify({'token': token}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Ruta protegida para admin
@app.route('/admin', methods=['GET'])
@requires_role('admin')
def admin_dashboard():
    return jsonify({"message": "Panel de Administrador"}), 200

# Ruta protegida para cliente
@app.route('/cliente', methods=['GET'])
@requires_role('cliente')
def cliente_dashboard():
    return jsonify({"message": "Panel de Cliente"}), 200

if __name__ == '__main__':
    app.run(debug=True)