from flask import Flask, jsonify, request
from flask_jwt_extended import (JWTManager, jwt_required, create_access_token, create_refresh_token, get_jwt_identity)
from loguru import logger
import os
from datetime import timedelta
import re 
from dotenv import load_dotenv
import psycopg2
from psycopg2 import sql
import bcrypt

###### Cargar el archivo .env
load_dotenv()

###### Setup de constantes
#dirs
DATA_DIR = os.getenv("DATA_DIR", "data")
LOG_DIR = os.getenv("LOG_DIR", "log")
#web app
PORT = int(os.getenv("PORT", 5000))
JWT_SECRET = os.getenv("JWT_SECRET", "super-secret")
JWT_EXPIRATION = int(os.getenv("JWT_EXPIRATION", 30))
REFRESH_EXPIRATION = int(os.getenv("JWT_EXPIRATION", 1))
#Para el sanitizado de datos.
#Todo: colocarlos en la DB
MIN_PASSWORD = int(os.getenv("MIN_PASSWORD", 8))
MAX_PASSWORD = int(os.getenv("MAX_PASSWORD", 50))
MIN_USERNAME = int(os.getenv("MIN_USERNAME", 3))
MAX_USERNAME = int(os.getenv("MAX_USERNAME", 24))

#db data
DB_HOST = os.getenv("DB_HOST","127.0.0.1")
DB_PORT = int(os.getenv("DB_PORT", 5432))
DB_NAME = os.getenv("DB_NAME","config_db")
DB_USER = os.getenv("DB_USER","uconfig")
DB_PASSWORD = os.getenv("DB_PASSWORD", "admin44444")

###### Globales
logger.add(os.path.join(LOG_DIR, "app.log"), rotation="50 MB")  # log file
dbconnection = None
dbcursor = None
app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = JWT_SECRET 
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=JWT_EXPIRATION)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=REFRESH_EXPIRATION)
jwt = JWTManager(app)

###### Funciones de base de datos 
def connect_to_db():
    try:
        # Establecer la conexión con la base de datos
        connection = psycopg2.connect(
            host=DB_HOST,
            port=DB_PORT,
            dbname=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD
        )
        cursor = connection.cursor()
        return connection, cursor
        
    except Exception as e:
        logger.error(f"Could not connect to DB with user {DB_USER} to {DB_HOST}: {e}")
        print(f"Error: {e}")

###### Funciones de la logica del programa
# obtener la password hasheada del user, para verificar login
def get_password_hash(username):
    global dbconnection, dbcursor
    
    try:
        # Verificar si la conexión está cerrada y volver a abrirla si es necesario
        if dbconnection==None or dbconnection.closed:
            dbconnection, dbcursor = connect_to_db()
        
        # Construir la consulta de manera segura y ejecutarla
        query = sql.SQL("SELECT password_hash FROM users WHERE username = %s")
        dbcursor.execute(query, (username,))
        result = dbcursor.fetchone()
        
        # Verificar si se encontró el usuario
        if result is None:
            logger.error("User not found "+ username)
            raise ValueError("User not found")
        else:
            # Retornar el password_hash
            return result[0]
    except Exception as e:
        logger.error(f"Something goes wrong asking for password: {e}")
        raise Exception(f"Error while getting password_hash")

# obtener informacion del dispositivo ()
def get_device_data(device_id):
    global dbconnection, dbcursor
    
    try:
        # Verificar si la conexión está cerrada y volver a abrirla si es necesario
        if dbconnection==None or dbconnection.closed:
            dbconnection, dbcursor = connect_to_db()

        # Construir la consulta de manera segura y ejecutarla
        query = sql.SQL("SELECT name,device_type,config_file_path FROM devices WHERE id = %s")
        dbcursor.execute(query, (device_id,))
        result = dbcursor.fetchone()
        
        # Verificar si se encontró el usuario
        if result is None:
            logger.error("Device not found "+ device_id)
            raise ValueError("Dispositivo no encontrado")
        else:
            # Retornar el password_hash
            return result
        
    except Exception as e:
        logger.error(f"Something goes wrong asking for device: {e}")
        raise Exception(f"Error al obtener el device: {e}")

# Función para sanitizar y validar el username
def sanitize_username(username):
    if not username:
        return None
    username = username.strip()
    
    if len(username) < MIN_USERNAME or len(username) > MAX_USERNAME:
        return None
    
    # Validar que solo contenga letras, números y algunos caracteres especiales
    if not re.match(r'^[a-zA-Z0-9_-]+$', username):
        return None
    
    return username

# Función para sanitizar y validar el password
def sanitize_password(password):
    if not password:
        return None
    
    # Eliminar espacios en blanco al principio y al final
    password = password.strip()
    
    # Validar longitud (ejemplo: entre 8 y 50 caracteres)
    if len(password) < MIN_PASSWORD or len(password) > MAX_PASSWORD:
        return None
    
    return password

###### Endpoints y logica del servicio http

# security headers cuando implemente https
# @app.after_request
# def add_security_headers(response):
#     response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
#     response.headers['Content-Security-Policy'] = "default-src 'self'; object-src 'none'; base-uri 'self'; upgrade-insecure-requests;"
#     response.headers['X-Content-Type-Options'] = 'nosniff'
#     response.headers['X-Frame-Options'] = 'DENY'
#     response.headers['X-XSS-Protection'] = '1; mode=block'
#     response.headers['Referrer-Policy'] = 'no-referrer-when-downgrade'
#     response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
#     response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
#     return response

# Manejar errores de token expirado
@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    logger.warning(f"POST refresh expired token from {request.remote_addr}")
    return jsonify({"message": "Refresh token invalid", "error": "invalid_token"}), 401

# Manejar errores de token inválido
@jwt.invalid_token_loader
def invalid_token_callback(error):
    logger.warning(f"POST refresh invalid token from {request.remote_addr}")
    return jsonify({"message": "Refresh token invalid", "error": "invalid_token"}), 401

# Manejar errores de falta de token
@jwt.unauthorized_loader
def missing_token_callback(error):
    logger.warning(f"POST refresh empty token from {request.remote_addr}")
    return jsonify({"message": "Refresh token invalid", "error": "invalid_token"}), 401

@app.route('/login', methods=['POST'])
def login():
    #obtener el user y sanitizarlo 
    username = request.json.get('username', None)
    username = sanitize_username(username)

    #obtener el password, sanitizarlo y realizar el md5
    password = request.json.get('password', None)
    password = sanitize_password(password).encode('utf-8')
    hashed_password = ""
    try:
        hashed_password=get_password_hash(username).encode('utf-8')
    except ValueError:
        logger.warning(f"GET login from {request.remote_addr} got 401, asking for non existing user {username}")
        return jsonify({"error": "Bad username or password"}), 401 #error generico para no generar una vul de information disclosure "Cryptographic Failures" (A02:2021)
    except Exception:
        logger.error(f"GET login from {request.remote_addr} got 500, problem with DB connection")
        return jsonify({"error": "Generic Internal Server Error"}), 500
    
    if not(bcrypt.checkpw(password,hashed_password)):
        logger.warning(f"GET login from {request.remote_addr} got 401, wrong password")
        return jsonify({"error": "Bad username or password"}), 401 #error generico para no generar una vul de information disclosure "Cryptographic Failures" (A02:2021)
    else:
        access_token = create_access_token(identity=username)
        refresh_token = create_refresh_token(identity=username)
        logger.info(f"GET login from {request.remote_addr} got 200, username {username} is succesful")
        return jsonify(access_token=access_token, refresh_token=refresh_token)

@app.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    # Obtener la identidad del usuario desde el refresh token
    current_user = get_jwt_identity()
    # Crear un nuevo access token
    new_access_token = create_access_token(identity=current_user)
    logger.info(f"Successful new token from {request.remote_addr} for user{current_user} by refresh token ")
    return jsonify(access_token=new_access_token)

@app.route('/config', methods=['GET'])
@jwt_required()
def get_config():
    # Obtener el parámetro device_id
    device_id = request.args.get('device_id')
    # Validar que device_id sea un número
    if not device_id or not device_id.isdigit():
        logger.info(f"GET CONFIG from {request.remote_addr} got 400")
        return jsonify({"error": "Valid device_id required"}), 400

    # Verificar si el dispositivo existe
    device_data=None
    try:
        device_data = get_device_data(device_id)
    except:
        logger.info(f"GET config from {request.remote_addr} got 404")
        return jsonify({"error": "Device not found"}), 404

    # Obtener la ruta del archivo de configuración
    config_file = device_data[2]
    config_path = os.path.join(DATA_DIR, config_file)
    # Leer el archivo de configuración
    try:
        with open(config_path, 'r') as file:
            config = file.read()
    except FileNotFoundError:
        logger.error(f"GET config from {request.remote_addr} got 500: device file {config_path} not found")
        return jsonify({"error": "Configuration file not found"}), 500

    logger.info(f"GET config from {request.remote_addr} for device {device_id} got 200")
    return jsonify({"device_id": device_id,"device_name":device_data[1],"device_type":device_data[1], "config": config})

###### Main}
if __name__ == '__main__':
    logger.info(f"System Started: listening port {PORT}")
    app.run(host='0.0.0.0', port=PORT)