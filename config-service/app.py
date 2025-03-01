from flask import Flask, jsonify, request
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token, create_refresh_token,
    get_jwt_identity
)
from loguru import logger
import hashlib
import os
from datetime import timedelta
import re 
from dotenv import load_dotenv

# Cargar el archivo .env
load_dotenv()

# Path a los directorios con los archivos de configuracion
DATA_DIR = os.getenv("DATA_DIR", "data")
LOG_DIR = os.getenv("LOG_DIR", "log")
JWT_SECRET = os.getenv("JWT_SECRET", "super-secret")
DB_NAME = os.getenv("DB_NAME", "database.db")
PORT = int(os.getenv("PORT", 5000))
JWT_EXPIRATION = int(os.getenv("JWT_EXPIRATION", 30))
MIN_PASSWORD = int(os.getenv("MIN_PASSWORD", 8))
MAX_PASSWORD = int(os.getenv("MAX_PASSWORD", 50))
MIN_USERNAME = int(os.getenv("MIN_USERNAME", 3))
MAX_USERNAME = int(os.getenv("MAX_USERNAME", 24))

# Diccionario con los logs 
# TODO: reemplazar por db
device_configs = {
    "1": "device1.txt",
    "2": "device2.txt"
}
## Diccionar de usuarios 
users = {
    "admin": "5f4dcc3b5aa765d61d8327deb882cf99"
}

app = Flask(__name__)

# Configuración de JWT
app.config['JWT_SECRET_KEY'] = JWT_SECRET  # Cambia esto por una clave secreta segura en producción
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=30) 
jwt = JWTManager(app)

logger.add(os.path.join(DATA_DIR, "app.log"), rotation="50 MB")  # log file
def md5_hash(input_string):
    return hashlib.md5(input_string.encode()).hexdigest()

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

@app.route('/login', methods=['POST'])
def login():
    #obtener el user y sanitizarlo 
    # #TODO detectar y logear users invalidos por intentos de SQL inyection
    username = request.json.get('username', None)
    username = sanitize_username(username)

    #obtener el password, sanitizarlo y realizar el md5
    password = request.json.get('password', None)
    password = sanitize_password(password)
    password_hash = md5_hash(password)

    if username not in users or users[username] != password_hash:
        logger.error(f"GET login from {request.remote_addr} got 401: username or password wrong")
        return jsonify({"error": "Bad username or password"}), 401
    
    access_token = create_access_token(identity=username)
    refresh_token = create_refresh_token(identity=username)
    logger.info(f"Successful login from {request.remote_addr} for username: {username}")
    return jsonify(access_token=access_token, refresh_token=refresh_token)

@app.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)  # Usar jwt_required con refresh=True
def refresh():
    # Obtener la identidad del usuario desde el refresh token
    current_user = get_jwt_identity()
    # Crear un nuevo access token
    new_access_token = create_access_token(identity=current_user)
    return jsonify(access_token=new_access_token)

@app.route('/config', methods=['GET'])
@jwt_required()
def get_config():
    # Obtener el parámetro device_id
    device_id = request.args.get('device_id')
    print("device_id", device_id)
    # Validar que device_id sea un número
    if not device_id or not device_id.isdigit():
        logger.info(f"GET CONFIG from {request.remote_addr} got 400")
        return jsonify({"error": "Valid device_id required"}), 400

    # Verificar si el dispositivo existe
    if device_id not in device_configs:
        logger.info(f"GET config from {request.remote_addr} got 404")
        return jsonify({"error": "Device not found"}), 404

    # Obtener la ruta del archivo de configuración
    config_file = device_configs[device_id]
    config_path = os.path.join(DATA_DIR, config_file)
    print(config_path)

    # Leer el archivo de configuración
    try:
        with open(config_path, 'r') as file:
            config = file.read()
    except FileNotFoundError:
        logger.error(f"GET config from {request.remote_addr} got 500: device file {config_path} not found")
        return jsonify({"error": "Configuration file not found"}), 500

    logger.info(f"GET config from {request.remote_addr} for device {device_id} got 200")
    return jsonify({"device_id": device_id, "config": config})

@app.route('/deviceList', methods=['GET'])
@jwt_required()
def get_deviceList():
    device_list = list(device_configs.keys())
    print(device_list)
    logger.info(f"GET deviceList from {request.remote_addr} for device got 200")
    return jsonify({"device_list": device_list})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=PORT)
    logger.info(f"System Started: listening port{PORT}")