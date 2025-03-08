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
import requests
from loguru import logger
from flask_jwt_extended import decode_token
from datetime import datetime, timezone
import json

###### Cargar el archivo .env
load_dotenv()

###### Setup de constantes
#dirs
DATA_DIR = os.getenv("DATA_DIR", "data")
LOG_DIR = os.getenv("LOG_DIR", "log")
#web app
PORT = int(os.getenv("PORT", 8080))
JWT_SECRET = os.getenv("JWT_SECRET", "super-secret")
JWT_EXPIRATION = int(os.getenv("JWT_EXPIRATION", 30))
REFRESH_EXPIRATION = int(os.getenv("JWT_EXPIRATION", 1))

#Para el sanitizado de datos.
MIN_PASSWORD = int(os.getenv("MIN_PASSWORD", 8))
MAX_PASSWORD = int(os.getenv("MAX_PASSWORD", 50))
MIN_USERNAME = int(os.getenv("MIN_USERNAME", 3))
MAX_USERNAME = int(os.getenv("MAX_USERNAME", 24))

#db data
DB_HOST = os.getenv("DB_HOST","127.0.0.1")
DB_PORT = int(os.getenv("DB_PORT", 5432))
DB_NAME = os.getenv("DB_NAME","analysis_db")
DB_USER = os.getenv("DB_USER","uanalysis")
DB_PASSWORD = os.getenv("DB_PASSWORD", "admin55555")

#config service data
CONFIG_USER=os.getenv("CONFIG_USER","uanalysis")
CONFIG_PASSWORD=os.getenv("CONFIG_PASSWORD","mlchallenge2025")
CONFIG_SERVICE_URL=os.getenv("CONFIG_SERVICE_URL","http://127.0.0.1:5000")

###### Globales
logger.add(os.path.join(LOG_DIR, "app.log"), rotation="50 MB")  # log file
access_token = None
refresh_token = None
dbconnection = None
dbcursor = None
app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = JWT_SECRET 
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=JWT_EXPIRATION)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=REFRESH_EXPIRATION)
jwt = JWTManager(app)

# Diccionario con los diferentes analizadores para distintos dispositivos
devices_analizer_list = {}


### Clases
class Finding:
    def __init__(self, name, analyzer, line_number, severity):
        self.name = name
        self.analyzer = analyzer
        self.line_number = line_number
        self.severity = severity

    def to_json(self):
        # Convertimos el objeto a un diccionario y luego a JSON
        return json.dumps({
            "name": self.name,
            "analyzer": self.analyzer,
            "line_number": self.line_number,
            "severity": self.severity
        }, indent=4)  # indent=4 para formato legible

    def to_string(self):
        # Convertimos el objeto a una cadena en formato propiedad: valor
        return (
            f"name: {self.name}\n"
            f"analyzer: {self.analyzer}\n"
            f"line_number: {self.line_number}\n"
            f"severity: {self.severity}"
        )


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
        print("Result:",result)
        
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


def perform_login():
    global config_token, refresh_token
    print("trying to log in")
    login_data = {
        "username": CONFIG_USER,
        "password": CONFIG_PASSWORD
    }
    
    try:
        login_response = requests.post(f"{CONFIG_SERVICE_URL}/login", json=login_data)
        
        if login_response.status_code == 200:
            tokens = login_response.json()
            config_token = tokens["access_token"]
            refresh_token = tokens["refresh_token"]
            logger.info("Login successful")
            return config_token
        else:
            logger.error(f"Login failed with status code {login_response.status_code}: {login_response.json().get('error')}")
            raise Exception("Login failed")
    except Exception as e:
        logger.error(f"Something went wrong during login: {e}")
        raise Exception("Login failed")



def get_config_from_service(device_id):
    #return response code (o none si no hay respuesta) y el json de respuesta en caso satisfactorio
    retryCount=3
    while retryCount>=0:
        try:
            token = perform_login()
            print("token",token,CONFIG_SERVICE_URL,CONFIG_USER,CONFIG_SERVICE_URL)
        except:
            return None, None
        headers = {
            'Authorization': f'Bearer {token}'
        }
        try:
            response = requests.get(CONFIG_SERVICE_URL+"/config", headers=headers, params={"device_id": 1})
            if response.status_code == 200:
                logger.info(f"Getting info for device is ok from config server")
                return 200,response.json()
            elif response.status_code == 401:
                logger.warning(f"Authorization error getting config service (maybe expired or invalid token), Retry countdown: {retryCount}")
            elif response.status_code == 404:
                return 404, None
        except Exception as e:
            logger.warning(f"Error geting device_id info: {e}. Retry countdown: {retryCount}")
        retryCount -=1
    return None,None


#Analizador que busca passwords
def pwd_finder(config_data,device_type):
    findings = []
    return findings

def create_analizer_dic():
    global devices_analizer_list

    devices_analizer_list["switch"]= [pwd_finder]
    devices_analizer_list["router"]= [pwd_finder]

def analize_device(config_data,device_type):
    global devices_analizer_list
    findings = []
    if device_type not in devices_analizer_list:
        raise Exception("There is no analizer for this type of device")
    for analizer in devices_analizer_list:

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

@app.route('/analize', methods=['GET'])
@jwt_required()
def get_analize():
    # Obtener el parámetro device_id
    device_id = request.args.get('device_id')
    # Validar que device_id sea un número
    if not device_id or not device_id.isdigit():
        logger.info(f"GET analize from {request.remote_addr} got 400")
        return jsonify({"error": "Valid device_id required"}), 400

    # Verificar si el dispositivo existe
    print("going to get info")
    response_code, config_respone = get_config_from_service(device_id)
    if response_code==None:
        logger.error(f"GET analyze from {request.remote_addr} got 500: is not posible to get info from config server")
        return jsonify({"error": "Generic Internal server error"}), 500
    else:
        if response_code==404:
            logger.error(f"GET analyze from {request.remote_addr} got 404: device not found on config server")
            return jsonify({"error": "Device not found"}), 404
        elif response_code==200:
            logger.info((f"GET analyze from {request.remote_addr} got 200: Requested analysis"))
            device_configuration=config_respone["config"]
            print("CONFIG",device_configuration)
            # analize
            analysis_id=1
            analysis_report=""
            # save report
            # return aswer
            return jsonify({"device_id": device_id,"device_name":config_respone["device_name"],"device_type":config_respone["device_type"], "analysis_id":analysis_id,"analysis_result":analysis_report})

###### Main}
if __name__ == '__main__':
    logger.info(f"System Started: listening port {PORT}")
    app.run(host='0.0.0.0', port=PORT)