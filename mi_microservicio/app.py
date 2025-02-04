from flask import Flask, jsonify, request,render_template
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
        print("Conexión a la base de datos establecida correctamente.")
        return conn
    except Exception as e:
        print("Error al conectar con la base de datos:", e)
        return None

# Función para generar una clave única usando el user_id del usuario
def generar_clave(user_id):
    # Usar SHA-256 para generar una clave de 32 bytes (256 bits)
    from cryptography.hazmat.primitives import hashes
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(str(user_id).encode('utf-8'))
    clave = digest.finalize()
    print(f"Clave generada para user_id={user_id}: {clave.hex()}")
    return clave

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
    # Retornar el IV, el tag y los datos encriptados (concatenados y codificados en Base64)
    resultado = base64.b64encode(iv + cifrador.tag + datos_encriptados).decode('utf-8')
    print(f"Datos encriptados: {resultado}")
    return resultado

# Función para desencriptar datos
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

    print(f"IV: {iv.hex()}")
    print(f"Tag: {tag.hex()}")
    print(f"Datos encriptados: {datos_encriptados.hex()}")

    try:
        # Crear el cifrador AES en modo GCM
        cifrador = Cipher(algorithms.AES(clave), modes.GCM(iv, tag), backend=default_backend()).decryptor()
        # Desencriptar los datos
        datos_padded = cifrador.update(datos_encriptados) + cifrador.finalize()
        # Quitar el padding
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        datos = unpadder.update(datos_padded) + unpadder.finalize()
        print(f"Datos desencriptados: {datos.decode('utf-8')}")
        return datos.decode('utf-8')
    except Exception as e:
        print(f"Error al desencriptar: {e}")
        return None
    
@app.route('/usuarios/<int:user_id>', methods=['PUT'])
def actualizar_usuario(user_id):
    data = request.get_json()
    
    # Obtener los campos de la solicitud (pueden ser nulos o vacíos)
    nombre = data.get('nombre')
    correo = data.get('correo')
    ci = data.get('ci')
    numero_telefono = data.get('numero_telefono')
    direccion = data.get('direccion')
    
    # Conectar a la base de datos
    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "No se pudo conectar a la base de datos"}), 500

    try:
        cur = conn.cursor()
        
        # Verificar si el usuario existe
        cur.execute("SELECT user_id FROM usuarios WHERE user_id = %s;", (user_id,))
        if cur.fetchone() is None:
            cur.close()
            conn.close()
            return jsonify({"error": "Usuario no encontrado"}), 404

        # Generar la clave para encriptar los datos (basada en el user_id)
        clave = generar_clave(user_id)

        # Preparar los campos para la actualización
        update_fields = []
        update_values = []

        # Verificar si el campo está presente en la solicitud (incluso si está vacío)
        if 'nombre' in data:
            nombre_encriptado = encriptar(nombre if nombre is not None else "", clave)
            update_fields.append("nombre = %s")
            update_values.append(nombre_encriptado)

        if 'correo' in data:
            correo_encriptado = encriptar(correo if correo is not None else "", clave)
            update_fields.append("correo = %s")
            update_values.append(correo_encriptado)

        if 'ci' in data:
            ci_encriptado = encriptar(ci if ci is not None else "", clave)
            update_fields.append("ci = %s")
            update_values.append(ci_encriptado)

        if 'numero_telefono' in data:
            numero_telefono_encriptado = encriptar(numero_telefono if numero_telefono is not None else "", clave)
            update_fields.append("numero_telefono = %s")
            update_values.append(numero_telefono_encriptado)

        if 'direccion' in data:
            direccion_encriptado = encriptar(direccion if direccion is not None else "", clave)
            update_fields.append("direccion = %s")
            update_values.append(direccion_encriptado)

        # Si no hay campos para actualizar, retornar un error
        if not update_fields:
            cur.close()
            conn.close()
            return jsonify({"error": "No se proporcionaron campos válidos para actualizar"}), 400

        # Construir la consulta SQL dinámicamente
        query = f"""
            UPDATE usuarios 
            SET {', '.join(update_fields)}
            WHERE user_id = %s;
        """
        update_values.append(user_id)

        # Ejecutar la consulta
        cur.execute(query, tuple(update_values))
        conn.commit()
        cur.close()
        conn.close()

        return jsonify({"message": "Usuario actualizado exitosamente"}), 200

    except Exception as e:
        print(f"Error en el endpoint PUT /usuarios/{user_id}: {e}")
        return jsonify({"error": str(e)}), 500
# Endpoint para obtener un usuario por su user_id
@app.route('/usuarios/<int:user_id>', methods=['GET'])
def get_usuario(user_id):
    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "No se pudo conectar a la base de datos"}), 500

    try:
        cur = conn.cursor()
        # Consulta para obtener el usuario por user_id
        cur.execute("SELECT user_id, nombre, ci, numero_telefono, correo, direccion FROM usuarios WHERE user_id = %s;", (user_id,))
        usuario = cur.fetchone()
        cur.close()
        conn.close()

        if usuario is None:
            print(f"Usuario con user_id={user_id} no encontrado.")
            return jsonify({"error": "Usuario no encontrado"}), 404

        # Desencriptar los datos del usuario
        user_id = usuario[0]
        clave = generar_clave(user_id)

        print(f"Desencriptando datos para user_id={user_id}...")
        usuario_dict = {
            "user_id": user_id,
            "nombre": desencriptar(usuario[1], clave),
            "ci": desencriptar(usuario[2], clave),
            "numero_telefono": desencriptar(usuario[3], clave),
            "correo": desencriptar(usuario[4], clave),
            "direccion": desencriptar(usuario[5], clave)
        }

        print(f"Usuario obtenido: {usuario_dict}")
        return jsonify(usuario_dict)

    except Exception as e:
        print(f"Error en el endpoint /usuarios/<int:user_id>: {e}")
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
        print("Faltan campos requeridos en la solicitud.")
        return jsonify({"error": "Todos los campos son requeridos"}), 400

    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "No se pudo conectar a la base de datos"}), 500

    try:
        cur = conn.cursor()
        # Insertar el usuario para obtener su user_id
        cur.execute(
            "INSERT INTO usuarios (nombre, ci, numero_telefono, correo, direccion) VALUES (%s, %s, %s, %s, %s) RETURNING user_id;",
            (nombre, ci, numero_telefono, correo, direccion)
        )
        user_id = cur.fetchone()[0]
        print(f"Usuario creado con user_id={user_id}.")

        # Generar la clave única para el usuario
        clave = generar_clave(user_id)

        # Encriptar los datos sensibles
        print("Encriptando datos...")
        nombre_encriptado = encriptar(nombre, clave)
        ci_encriptado = encriptar(ci, clave)
        numero_telefono_encriptado = encriptar(numero_telefono, clave)
        correo_encriptado = encriptar(correo, clave)
        direccion_encriptado = encriptar(direccion, clave)

        # Actualizar el usuario con los datos encriptados
        cur.execute(
            "UPDATE usuarios SET nombre = %s, ci = %s, numero_telefono = %s, correo = %s, direccion = %s WHERE user_id = %s;",
            (nombre_encriptado, ci_encriptado, numero_telefono_encriptado, correo_encriptado, direccion_encriptado, user_id)
        )
        conn.commit()
        cur.close()
        conn.close()

        print("Usuario actualizado con datos encriptados.")
        return jsonify({"message": "Usuario creado exitosamente", "user_id": user_id}), 201

    except Exception as e:
        print(f"Error en el endpoint /usuarios: {e}")
        return jsonify({"error": str(e)}), 500
    
    
@app.route('/perfil/<int:user_id>', methods=['GET'])
def perfil(user_id):
    # Aquí podrías enviar el user_id a la plantilla si lo necesitas para alguna lógica
    return render_template('perfil.html', user_id=user_id)

if __name__ == '__main__':
    app.run(debug=True, port=5001)  # Cambia el puerto si es necesario