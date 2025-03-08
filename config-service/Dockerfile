FROM python:3.9-slim

# Crear un usuario y grupo sin privilegios
RUN groupadd -r uconfigservice && useradd -r -g uconfigservice uconfigservice
RUN apt-get update && apt-get install -y iproute2 procps nano net-tools

# Crear el directorio de la aplicación
WORKDIR /app

# Copiar los archivos de requisitos e instalar dependencias
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar el código de la aplicación
COPY . .

EXPOSE 5000
# Crear la carpeta configs si no existe
# RUN mkdir -p /app/data && chown uconfigservice:uconfigservice /app/data
# RUN mkdir -p /app/log && chown uconfigservice:uconfigservice /app/log

# Copiar los archivos de configuración
COPY --chown=uconfigservice:uconfigservice data /app/data
COPY --chown=uconfigservice:uconfigservice log /app/log

# Cambiar al usuario sin privilegios
USER uconfigservice

# Comando para ejecutar la aplicación
CMD ["python", "app.py", ">","running.txt"]