FROM python:3.9-slim

# Crear un usuario y grupo sin privilegios
RUN groupadd -r uanalysisservice && useradd -r -g uanalysisservice uanalysisservice
RUN apt-get update && apt-get install -y iproute2 procps nano net-tools

# Crear el directorio de la aplicación
WORKDIR /app

# Copiar los archivos de requisitos e instalar dependencias
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar el código de la aplicación
COPY . .

EXPOSE 8080
# Crear la carpeta configs si no existe
# RUN mkdir -p /app/data && chown uanalysisservice:uanalysisservice /app/data
RUN mkdir -p /app/log && chown uanalysisservice:uanalysisservice /app/log

# Copiar los archivos de configuración
# COPY --chown=uanalysisservice:uanalysisservice data /app/data

# Cambiar al usuario sin privilegios
USER uanalysisservice

# Comando para ejecutar la aplicación
CMD ["python", "app.py"]