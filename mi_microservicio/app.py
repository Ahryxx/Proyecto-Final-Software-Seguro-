from flask import Flask, jsonify, request,render_template
import psycopg2
from config import SECRET_KEY,DBCONNECT,DBCONNECTAUDIT
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
import base64
from functools import wraps
from flask import request, jsonify
import jwt
import datetime


app = Flask(__name__)

# Conexión a la base de datos
# Nueva función de conexión usando la URL completa
def get_db_connection():
    try:
        conn = psycopg2.connect(
            DBCONNECT
        )
        print("Conexión a la base de datos establecida correctamente.")
        return conn
    except Exception as e:
        print("Error al conectar con la base de datos:", e)
        return None
    
def get_audit_db_connection():
    try:
        conn = psycopg2.connect(
            DBCONNECTAUDIT
        )
        print("Conexión a la base de datos de auditoría establecida correctamente.")
        return conn
    except Exception as e:
        print("Error al conectar con la base de datos de auditoría:", e)
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
    
    nombre = data.get('nombre')
    correo = data.get('correo')
    ci = data.get('ci')
    numero_telefono = data.get('numero_telefono')
    direccion = data.get('direccion')
    fecha_expiracion = data.get('fecha_expiracion')
    
    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "No se pudo conectar a la base de datos"}), 500

    try:
        cur = conn.cursor()
        
        cur.execute("SELECT user_id FROM usuarios WHERE user_id = %s;", (user_id,))
        if cur.fetchone() is None:
            cur.close()
            conn.close()
            return jsonify({"error": "Usuario no encontrado"}), 404

        clave = generar_clave(user_id)

        cur.execute("""
            SELECT nombre, correo, ci, numero_telefono, direccion, fecha_expiracion 
            FROM usuarios 
            WHERE user_id = %s;
        """, (user_id,))
        usuario_actual = cur.fetchone()

        usuario_actual_dict = {
            "nombre": desencriptar(usuario_actual[0], clave),
            "correo": desencriptar(usuario_actual[1], clave),
            "ci": desencriptar(usuario_actual[2], clave),
            "numero_telefono": desencriptar(usuario_actual[3], clave),
            "direccion": desencriptar(usuario_actual[4], clave),
            "fecha_expiracion": usuario_actual[5].strftime('%Y-%m-%d') if usuario_actual[5] else None
        }

        update_fields = []
        update_values = []
        cambios = []

        if 'nombre' in data:
            nuevo_nombre = nombre if nombre is not None else ""
            if nuevo_nombre != usuario_actual_dict["nombre"]:
                nombre_encriptado = encriptar(nuevo_nombre, clave)
                update_fields.append("nombre = %s")
                update_values.append(nombre_encriptado)
                cambios.append(f"nombre: {usuario_actual_dict['nombre']} -> {nuevo_nombre}")

        if 'correo' in data:
            nuevo_correo = correo if correo is not None else ""
            if nuevo_correo != usuario_actual_dict["correo"]:
                correo_encriptado = encriptar(nuevo_correo, clave)
                update_fields.append("correo = %s")
                update_values.append(correo_encriptado)
                cambios.append(f"correo: {usuario_actual_dict['correo']} -> {nuevo_correo}")

        if 'ci' in data:
            nuevo_ci = ci if ci is not None else ""
            if nuevo_ci != usuario_actual_dict["ci"]:
                ci_encriptado = encriptar(nuevo_ci, clave)
                update_fields.append("ci = %s")
                update_values.append(ci_encriptado)
                cambios.append(f"ci: {usuario_actual_dict['ci']} -> {nuevo_ci}")

        if 'numero_telefono' in data:
            nuevo_numero_telefono = numero_telefono if numero_telefono is not None else ""
            if nuevo_numero_telefono != usuario_actual_dict["numero_telefono"]:
                numero_telefono_encriptado = encriptar(nuevo_numero_telefono, clave)
                update_fields.append("numero_telefono = %s")
                update_values.append(numero_telefono_encriptado)
                cambios.append(f"numero_telefono: {usuario_actual_dict['numero_telefono']} -> {nuevo_numero_telefono}")

        if 'direccion' in data:
            nueva_direccion = direccion if direccion is not None else ""
            if nueva_direccion != usuario_actual_dict["direccion"]:
                direccion_encriptado = encriptar(nueva_direccion, clave)
                update_fields.append("direccion = %s")
                update_values.append(direccion_encriptado)
                cambios.append(f"direccion: {usuario_actual_dict['direccion']} -> {nueva_direccion}")

        if 'fecha_expiracion' in data:
            nueva_fecha = fecha_expiracion if fecha_expiracion else None
            if nueva_fecha != usuario_actual_dict["fecha_expiracion"]:
                update_fields.append("fecha_expiracion = %s")
                update_values.append(nueva_fecha)
                cambios.append(f"fecha_expiracion: {usuario_actual_dict['fecha_expiracion']} -> {nueva_fecha}")

        if not update_fields:
            cur.close()
            conn.close()
            return jsonify({"error": "No se proporcionaron campos válidos para actualizar"}), 400

        query = f"""
            UPDATE usuarios 
            SET {', '.join(update_fields)}
            WHERE user_id = %s;
        """
        update_values.append(user_id)

        cur.execute(query, tuple(update_values))
        conn.commit()
        cur.close()
        conn.close()

        if cambios:
            audit_conn = get_audit_db_connection()
            if audit_conn:
                audit_cur = audit_conn.cursor()
                audit_cur.execute(
                    "INSERT INTO audit_logs (user_id, action, details) VALUES (%s, %s, %s)",
                    (user_id, 'actualizacion_datos', f"El usuario {user_id} modificó: {', '.join(cambios)}")
                )
                audit_conn.commit()
                audit_cur.close()
                audit_conn.close()

        return jsonify({"message": "Usuario actualizado exitosamente"}), 200

    except Exception as e:
        print(f"Error en el endpoint PUT /usuarios/{user_id}: {e}")
        return jsonify({"error": str(e)}), 500
# Endpoint para obtener un usuario por su user_id
@app.route('/usuarios/<int:user_id>', methods=['GET'])
@requires_role('cliente')
def get_usuario(user_id):
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({"error": "Token no proporcionado"}), 401

    try:
        token = token.split(" ")[1]
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        token_user_id = payload.get('user_id')

        if token_user_id != user_id:
            return jsonify({"error": "Acceso no autorizado"}), 403

        conn = get_db_connection()
        if conn is None:
            return jsonify({"error": "No se pudo conectar a la base de datos"}), 500

        cur = conn.cursor()
        cur.execute("""
            SELECT user_id, nombre, ci, numero_telefono, correo, direccion, fecha_expiracion 
            FROM usuarios 
            WHERE user_id = %s;
        """, (user_id,))
        usuario = cur.fetchone()
        cur.close()
        conn.close()

        if usuario is None:
            print(f"Usuario con user_id={user_id} no encontrado.")
            return jsonify({"error": "Usuario no encontrado"}), 404

        clave = generar_clave(user_id)

        print(f"Desencriptando datos para user_id={user_id}...")
        usuario_dict = {
            "user_id": user_id,
            "nombre": desencriptar(usuario[1], clave),
            "ci": desencriptar(usuario[2], clave),
            "numero_telefono": desencriptar(usuario[3], clave),
            "correo": desencriptar(usuario[4], clave),
            "direccion": desencriptar(usuario[5], clave),
            "fecha_expiracion": usuario[6].strftime('%Y-%m-%d') if usuario[6] else None
        }

        audit_conn = get_audit_db_connection()
        if audit_conn:
            audit_cur = audit_conn.cursor()
            audit_cur.execute(
                "INSERT INTO audit_logs (user_id, action, details) VALUES (%s, %s, %s)",
                (user_id, 'acceso_datos', f"El usuario {user_id} accedió a sus datos.")
            )
            audit_conn.commit()
            audit_cur.close()
            audit_conn.close()

        return jsonify(usuario_dict)

    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expirado"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Token inválido"}), 401
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
    

# Primero, separamos la ruta de renderizado y la ruta de datos
@app.route('/usuarios/resumen', methods=['GET'])
def resumen_page():
    # Similar a la ruta de perfil, solo renderiza la plantilla
    return render_template('resumen.html')

# Nueva ruta para obtener los datos del resumen
@app.route('/api/usuarios/resumen', methods=['GET'])
@requires_role('admin')
def obtener_resumen_usuarios():
    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "No se pudo conectar a la base de datos"}), 500

    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT u.user_id, u.nombre, u.ci, u.numero_telefono, u.correo, u.direccion 
            FROM usuarios u
            INNER JOIN login l ON u.user_id = l.id
            WHERE l.role = 'cliente';
        """)
        
        usuarios = cur.fetchall()
        cur.close()
        conn.close()

        usuarios_resumen = []

        for usuario in usuarios:
            user_id = usuario[0]
            clave = generar_clave(user_id)

            datos_usuario = {
                "nombre": desencriptar(usuario[1], clave),
                "ci": desencriptar(usuario[2], clave),
                "numero_telefono": desencriptar(usuario[3], clave),
                "correo": desencriptar(usuario[4], clave),
                "direccion": desencriptar(usuario[5], clave)
            }

            campos_llenos = {k: v for k, v in datos_usuario.items() if v}

            if "nombre" in campos_llenos:
                usuarios_resumen.append({
                    "nombre": campos_llenos.pop("nombre"),
                    "campos_llenos": list(campos_llenos.keys())
                })

        return jsonify(usuarios_resumen)

    except Exception as e:
        print(f"Error en el endpoint GET /api/usuarios/resumen: {e}")
        return jsonify({"error": str(e)}), 500
    
@app.route('/perfil/<int:user_id>', methods=['GET'])
def perfil(user_id):
    # Aquí podrías enviar el user_id a la plantilla si lo necesitas para alguna lógica
    return render_template('perfil.html', user_id=user_id)

if __name__ == '__main__':
    app.run(debug=True, port=5001)  # Cambia el puerto si es necesario