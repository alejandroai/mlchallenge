import pytest
import requests

# URL base de la API
BASE_URL = "http://localhost:8080"

# Datos de prueba para el login
VALID_DEVICE_ID = 1
INVALID_REPORT_ID = 999
FORBIDEN_REPORT_ID = 1
VALID_REPORT_ID=2
INVALID_DEVICE_ID = 999

# Fixture para cargar la contraseña desde un archivo
@pytest.fixture
def supply_password():
    with open('secret.tdata', 'r') as file:
        password = file.read().strip()  # Lee y elimina espacios en blanco
    return password

# Función para obtener el token de acceso
def get_access_token(supply_password):  # Requiere supply_password como argumento
    LOGIN_DATA = {
        "username": "analyst_test",
        "password": supply_password  # Usar el valor de supply_password
    }
    print("*" * 10, LOGIN_DATA)
    response = requests.post(f"{BASE_URL}/login", json=LOGIN_DATA)
    assert response.status_code == 200
    return response.json()["access_token"]

# Prueba para el endpoint de login
def test_login(supply_password):  # Pasar supply_password como argumento
    LOGIN_DATA = {
        "username": "analyst_test",
        "password": supply_password  # Usar el valor de supply_password
    }
    response = requests.post(f"{BASE_URL}/login", json=LOGIN_DATA)
    assert response.status_code == 200
    assert "access_token" in response.json()
    assert "refresh_token" in response.json()

# Prueba para el endpoint de obtener reporte
def test_get_report(supply_password):  # Pasar supply_password como argumento
    access_token = get_access_token(supply_password)  # Pasar supply_password
    headers = {"Authorization": f"Bearer {access_token}"}
    report_id = VALID_REPORT_ID  # ID de reporte de prueba
    response = requests.get(f"{BASE_URL}/report?report_id={report_id}", headers=headers)
    assert response.status_code == 200
    assert "id" in response.json()
    assert "owner_id" in response.json()
    assert "result" in response.json()

def test_get_forbidden_report(supply_password):  # Pasar supply_password como argumento
    access_token = get_access_token(supply_password)  # Pasar supply_password
    headers = {"Authorization": f"Bearer {access_token}"}
    report_id = FORBIDEN_REPORT_ID  # ID de reporte de prueba
    response = requests.get(f"{BASE_URL}/report?report_id={report_id}", headers=headers)
    assert response.status_code == 401

# Prueba para el endpoint de análisis de dispositivo
def test_analyze_device(supply_password):  # Pasar supply_password como argumento
    access_token = get_access_token(supply_password)  # Pasar supply_password
    headers = {"Authorization": f"Bearer {access_token}"}
    device_id = VALID_DEVICE_ID  # ID de dispositivo de prueba
    response = requests.get(f"{BASE_URL}/analize?device_id={device_id}", headers=headers)
    print(response)
    assert response.status_code == 200
    assert "analisys_id" in response.json()
    assert "device_id" in response.json()
    assert "analysis_result" in response.json()

# Prueba para manejo de errores en el endpoint de login
def test_login_failure():
    invalid_data = {
        "username": "wronguser",
        "password": "wrongpass"
    }
    response = requests.post(f"{BASE_URL}/login", json=invalid_data)
    assert response.status_code == 401
    assert "error" in response.json()

def test_login_failure_wrong_pass():
    invalid_data = {
        "username": "analyst_test",
        "password": "wrongpass"
    }
    response = requests.post(f"{BASE_URL}/login", json=invalid_data)
    assert response.status_code == 401
    assert "error" in response.json()

# Prueba para manejo de errores en el endpoint de obtener reporte
def test_get_report_failure(supply_password):  # Pasar supply_password como argumento
    access_token = get_access_token(supply_password)  # Pasar supply_password
    headers = {"Authorization": f"Bearer {access_token}"}
    invalid_report_id = INVALID_REPORT_ID  # ID de reporte inválido
    response = requests.get(f"{BASE_URL}/report?report_id={invalid_report_id}", headers=headers)
    assert response.status_code == 404
    assert "error" in response.json()

# Prueba para manejo de errores en el endpoint de análisis de dispositivo
def test_analyze_device_failure(supply_password):  # Pasar supply_password como argumento
    access_token = get_access_token(supply_password)  # Pasar supply_password
    headers = {"Authorization": f"Bearer {access_token}"}
    invalid_device_id = INVALID_DEVICE_ID  # ID de dispositivo inválido
    response = requests.get(f"{BASE_URL}/analysis?device_id={invalid_device_id}", headers=headers)
    assert response.status_code == 404