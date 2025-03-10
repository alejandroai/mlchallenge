import pytest

@pytest.fixture
def supply_password():
    # Abre el archivo secret.tdata en modo lectura
    with open('secret.tdata', 'r') as file:
        # Lee el contenido del archivo
        password = file.read().strip()  # .strip() elimina espacios en blanco y saltos de línea
    return password