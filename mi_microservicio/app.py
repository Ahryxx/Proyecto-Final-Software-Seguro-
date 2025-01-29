from flask import Flask, jsonify, request
import psycopg2
from config import DB_HOST, DB_NAME, DB_USER, DB_PASSWORD, DB_PORT
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
import base64

app = Flask(__name__)

# Conexión a la base de datos
def get_db_connection():
    try:
        conn = psycopg2.connect(
            host=DB_HOST,
            database=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD,
            port=DB_PORT
        )
        return conn
    except Exception as e:
        print("Error al conectar con la base de datos:", e)
        return None

# Función para generar una clave única usando el id del usuario
def generar_clave(id_usuario):
    # Usar SHA-256 para generar una clave de 32 bytes (256 bits)
    from cryptography.hazmat.primitives import hashes
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(str(id_usuario).encode('utf-8'))
    return digest.finalize()

# Función para encriptar datos
def encriptar(datos, clave):
    # Generar un IV (Initialization Vector) aleatorio
    iv = os.urandom(16)
    # Crear el cifrador AES en modo GCM
    cifrador = Cipher(algorithms.AES(clave), modes.GCM(iv), backend=default_backend()).encryptor()
    # Aplicar padding a los datos si es necesario
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    datos_padded = padder.update(datos.encode('utf-8')) + padder.finalize()
    # Encriptar los datos
    datos_encriptados = cifrador.update(datos_padded) + cifrador.finalize()
    # Retornar el IV y los datos encriptados (concatenados)
    return base64.b64encode(iv + cifrador.tag + datos_encriptados).decode('utf-8')

def desencriptar(datos_encriptados, clave):
    try:
        datos_encriptados = base64.b64decode(datos_encriptados)
    except Exception as e:
        print(f"Error al decodificar la cadena: {e}")
        return None

    # Extraer el IV, el tag y los datos encriptados
    iv = datos_encriptados[:16]
    tag = datos_encriptados[16:32]
    datos_encriptados = datos_encriptados[32:]

    # Crear el cifrador AES en modo GCM
    cifrador = Cipher(algorithms.AES(clave), modes.GCM(iv, tag), backend=default_backend()).decryptor()
    # Desencriptar los datos
    datos_padded = cifrador.update(datos_encriptados) + cifrador.finalize()
    # Quitar el padding
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    datos = unpadder.update(datos_padded) + unpadder.finalize()
    return datos.decode('utf-8')

# Endpoint para obtener un usuario por su ID
@app.route('/usuarios/<int:id>', methods=['GET'])
def get_usuario(id):
    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "No se pudo conectar a la base de datos"}), 500

    try:
        cur = conn.cursor()
        cur.execute("SELECT id, nombre, ci, numero_telefono, correo, direccion FROM usuarios WHERE id = %s;", (id,))
        usuario = cur.fetchone()
        cur.close()
        conn.close()

        if usuario is None:
            return jsonify({"error": "Usuario no encontrado"}), 404

        # Desencriptar los datos del usuario
        id_usuario = usuario[0]
        clave = generar_clave(id_usuario)

        usuario_dict = {
            "id": id_usuario,
            "nombre": desencriptar(usuario[1], clave),
            "ci": desencriptar(usuario[2], clave),
            "numero_telefono": desencriptar(usuario[3], clave),
            "correo": desencriptar(usuario[4], clave),  # Desencriptar el correo electrónico
            "direccion": desencriptar(usuario[5], clave)
        }

        return jsonify(usuario_dict)

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Endpoint para crear un nuevo usuario
@app.route('/usuarios', methods=['POST'])
def crear_usuario():
    data = request.get_json()
    nombre = data.get('nombre')
    ci = data.get('ci')
    numero_telefono = data.get('numero_telefono')
    correo = data.get('correo')
    direccion = data.get('direccion')

    if not nombre or not ci or not numero_telefono or not correo or not direccion:
        return jsonify({"error": "Todos los campos son requeridos"}), 400

    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "No se pudo conectar a la base de datos"}), 500

    try:
        cur = conn.cursor()
        # Insertar el usuario para obtener su ID
        cur.execute(
            "INSERT INTO usuarios (nombre, ci, numero_telefono, correo, direccion) VALUES (%s, %s, %s, %s, %s) RETURNING id;",
            (nombre, ci, numero_telefono, correo, direccion)
        )
        id_usuario = cur.fetchone()[0]

        # Generar la clave única para el usuario
        clave = generar_clave(id_usuario)

        # Encriptar los datos sensibles, incluyendo el correo electrónico
        nombre_encriptado = encriptar(nombre, clave)
        ci_encriptado = encriptar(ci, clave)
        numero_telefono_encriptado = encriptar(numero_telefono, clave)
        correo_encriptado = encriptar(correo, clave)  # Encriptar el correo
        direccion_encriptado = encriptar(direccion, clave)

        # Actualizar el usuario con los datos encriptados
        cur.execute(
            "UPDATE usuarios SET nombre = %s, ci = %s, numero_telefono = %s, correo = %s, direccion = %s WHERE id = %s;",
            (nombre_encriptado, ci_encriptado, numero_telefono_encriptado, correo_encriptado, direccion_encriptado, id_usuario)
        )
        conn.commit()
        cur.close()
        conn.close()

        return jsonify({"message": "Usuario creado exitosamente", "id": id_usuario}), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)