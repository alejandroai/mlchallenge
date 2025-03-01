from flask import Flask, jsonify, request
from flask_httpauth import HTTPTokenAuth
from loguru import logger
import os

#path a los directorios con los archivos de configuracion
DATA_DIR="data" 
LOG_DIR="log"
PORT=5000

#diccionario con los logs 
#TODO: pasarlo a yaml
device_configs = {
    "1": "device1.txt",
    "2": "device2.txt"
}

app = Flask(__name__)
auth = HTTPTokenAuth(scheme='Bearer')
logger.add(os.path.join(DATA_DIR, "app.log"), rotation="50 MB") #log file

#TODO reemplazar por un archivo de tokens
tokens = { "admin" }

@auth.verify_token
def verify_token(token):
    print("verifing token",token)
    if token in tokens:
        return True

@app.route('/config', methods=['GET'])
@auth.login_required
def get_config():
     # Obtener el parámetro device_id
    device_id = request.args.get('device_id') 
    print("device_id",device_id)
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
@auth.login_required
def get_deviceList():     
    device_list = list(device_configs.keys())
    print(device_list)
    logger.info(f"GET deviceList from {request.remote_addr} for device got 200")
    return jsonify({"device_list": device_list})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=PORT)
    logger.info(f"System Started: listening port{PORT}")