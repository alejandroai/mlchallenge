
# mlchallenge
## Descripcion del challenge solicitado (extracto del correo)

Se debe desarrollar una solución que tenga 2 servicios para poder analizar el estado de seguridad de un dispositivo de red.

Un servicio orientado a disponibilizar la configuración de un dispositivo de red. Para este challenge vamos a otorgarles un archivo de texto que simule ser la configuración real.

Un servicio que tenga la responsabilidad de analizar el archivo de configuración. Este servicio debe comunicarse con el primero mencionado y utilizar la configuración obtenida como input a analizar. A su vez, debe contar con una interfaz (API) que disponibilice los resultados del analisis, los cuales deben estar perisistidos para poder ser accedidos en cualquier momento.

**Estructura Esperada del Challenge**
- Contenedores Docker:
- config-service: solo puede tener conectividad con analysis-service.
- analysis-service: debe poder ser accedido desde el host y tener conectividad con config-service.

**Desarrollo:**
- Definir APIs funcionales para cada servicio (config-service, analysis-service).
- La aplicación debe estar escrita en un lenguaje backend como Python, Go, Javascript o el que desee.
- analysis-service debe tener una comunicación con config-service y retornar un analisis de seguridad basado en la configuración recibida.
- Docker Compose: El candidato debe incluir un archivo docker-compose.yml que defina los contenedores y las redes.

**Seguridad: Todos los servicios deben estar autenticados.

**Documentación:**
- Documentación de los endpoints: Debe incluir la documentación de cada endpoint desarrollado y sus funcionalidades.
- Manual: Incluir un manual en formato PDF o Markdown que explique cómo utilizar la solución, incluyendo ejemplos de uso de las APIs y configuración de las redes Docker. Es válido el uso de diagramas.

**Extras:**
- Swagger: Se debe proporcionar una especificación de Swagger que describa todos los endpoints y su uso.
- Logs y Monitoreo Avanzado: Implementar una solución para monitorear y visualizar los logs en tiempo real.
- Tests Automatizados: Incluir pruebas unitarias y de integración para los servicios, utilizando herramientas como JUnit, PyTest. (Se puede proponer otra biblioteca).
- Seguridad: Autorización, cifrado de tráfico, entre otras oportunidades de hardening que aumenten la seguridad de la solución.

## Descripcion de la solucion

Para implementar la solucion opté por el lenguaje python y la libreria Flask. Todos los servicios web corren con una imagen hardenizada de nginx con la distro Alpine. Se utiliza guinicorn en los contenedores para levantar el servicio de Python Flask para no correrlo directamente, escuchando internamente dentro del contenedor en el puerto 8080. El nginx realiza un proxy reverso al mismo. Las dependencias de python en requeriments.txt setean la versión de cada librería ya que es una buena práctica.

Las credenciales que se encontraban en texto plano se separaron en archivo .env y .tdata que fueron agregados al .gitignore.

Se utilizar una librería para realizar los logs de ambas aplicaciones. 

Solo se armaron nat para el puerto 8080 del contenedor de analysis-service (accesible fuera del entorno docker) y para el contenedor swagger-web en el puerto 80. 

Cada aplicacion tiene su respectiva base de datos en el contenedor db. Las credenciales por defecto son reemplazadas por el script "set-users.sh" para tomar las variables de entorno

## Mejoras pendientes de implementacion:

- **refresh token:** implemente la funcionalidad de "refresh token" pero no se utilizó ni en el analisis
- **unificar modulos**: unificar funcionalidad de config-service y analysis-service para no tener que mantener dos códigos muy similares en cuanto a login y manejo de tokens y logs
- **KPI:** implementar una CA con un docker basico con alpine. Generar los certificados en los config-service y analysis-service. Enviar la solicitud de firma a esta CA. Cargar los certificados firmados y reinicar los servicio de nginx. Compartir el certificado de CA en el contenedor de analysis-service para que confie a traves de KPI en el certificado firmado del config-service. No sería recomendable, pero opcionalmente esta CA se podría instalar en la PC de las pruebas
- **utilizar usuario no root para los contenedores:** cree los usuarios y grupos, pero no llegue a implementar ejecutar los procesos con otro usuario que no sea root ya que es una mala práctica de seguridad dejar los servicios corriendo como root
-**endpoint ABM**: endpoint para gestionar usuarios y configuraciones
-**implementar endpoints para listar dispositivos:** 
-**implementar sistema de permisos para acceder a configuracion de dipositivo segun usuario**
-**configurar el pghba¨** de postgress para permitir conexiones solo de los contenedores config-service y analysis service. 
-**utlizar el header x-forwarder-for** para identificar a los clientes dentro de los logs. No llegué a modificar luego de implementar el cambio guinicorn 
 
## Me apoyé en la IA para:
- Documentacion y generación de swaggers
- Desarrollo de pruebas con pytest
- Estructura base del proyecto en docker


## Instrucciones para ejecutar el challenge

Requisitos:
- **Docker** (instalado y funcionando)
- **Python 3** (para ejecutar pytest pruebas)
- **Postman** (opcional, para pruebas manuales de la API)
- **Postman** (curl, para pruebas manuales de la API)
---

### 1. Descargar el código fuente

```bash
git clone https://github.com/alejandroai/mlchallenge.git
cd mlchallenge
```

---

### 2. Generar archivo `.env`

Crear el archivo `mlchallenge/.env` con el siguiente contenido:

```ini
UCONFIG_PASSWORD=tu_password_config
UANALYSIS_PASSWORD=tu_password_analysis
```

**Comentarios:**
- `UCONFIG_PASSWORD`: Contraseña para conectarse a la base de datos `config_db`.
- `UANALYSIS_PASSWORD`: Contraseña para conectarse a la base de datos `analysis_db`.

---

### 3. Crear archivo secreto para pruebas

Generar el archivo `tests/secret.tdata` con la contraseña compartida por correo:

```
PASSWORD_COMPARTIDA_POR_CORREO
```

---

### 4. Crear imágenes y ejecutar el proyecto

Desde la carpeta raíz, ejecutar:

```bash
docker-compose up --build
```

Esto levantara los siguientes contenedores:
- ** config-service: ** contiene el servicio que da la configuracion
- ** analysis-service: ** contiene el servicio que realiza y retorna los analisis/reportes
- ** db: ** contiene la base de datos del servicio de config-service y analysis-service
- ** swagger-web: ** contiene las web estaticas de los swagger 
---

### 5. Acceso a la API y documentación (Swagger)

Una vez levantado el proyecto, se puede consultar la documentación interactiva (Swagger UI) en:

- [http://127.0.0.1:8080/config-swg/](http://127.0.0.1:8080/config-swg/)
- [http://127.0.0.1:8080/analysis-swg/](http://127.0.0.1:8080/analysis-swg/)

**Nota:** La API estará expuesta en [http://127.0.0.1:8080](http://127.0.0.1:8080).

---

### 6. Pruebas con Postman (opcional)

Se puede importar la colección de Postman ubicada en la carpeta:

```
postman_export
```

---

### 7. Pruebas con `curl`

#### Linux:

**Login:**
```bash
curl -X POST http://127.0.0.1:8080/login   -H 'Content-Type: application/json'   -d '{"username": "analyst_test", "password": "PASSWORD_COMPARTIDA_POR_CORREO"}'
```

**Solicitar análisis (dispositivo válido `id=1`):**
```bash
curl -X GET 'http://127.0.0.1:8080/analize?device_id=1'   -H 'Authorization: Bearer TOKEN'
```

**Solicitar reporte:**
```bash
curl -X GET 'http://127.0.0.1:8080/report?report_id=1'   -H 'Authorization: Bearer TOKEN'
```

#### Windows:

**Login:**
```bash
curl -X POST ^
  http://127.0.0.1:8080/login ^
  -H "Content-Type: application/json" ^
  -d "{"username": "analyst_test", "password": "PASSWORD_COMPARTIDA_POR_CORREO"}"
```

**Solicitar análisis:**
```bash
curl -X GET ^
  "http://127.0.0.1:8080/analize?device_id=1" ^
  -H "Authorization: Bearer TOKEN"
```

**Solicitar reporte:**
```bash
curl -X GET ^
  "http://127.0.0.1:8080/report?report_id=1" ^
  -H "Authorization: Bearer TOKEN"
```

---

### 8. Ejecución de pruebas

#### Requisitos:
Instalar `pytest` (si no está instalado):

```bash
pip install pytest
```

#### Ejecutar pruebas:

```bash
cd tests
python -m pytest test.py --verbose
```


