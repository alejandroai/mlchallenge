FROM python:3.9-slim

# Crear un usuario y grupo sin privilegios
RUN groupadd -r uconfigservice && useradd -r -g uconfigservice uconfigservice
RUN apt-get update && apt-get install -y nginx procps

# Crear el directorio de la aplicación
WORKDIR /app

# Copiar los archivos de requisitos e instalar dependencias
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar el código de la aplicación
COPY . .

# Configurar Nginx
COPY nginx.conf /etc/nginx/nginx.conf

EXPOSE 5000
# Crear la carpeta configs si no existe
RUN mkdir -p /app/data && chown uconfigservice:uconfigservice /app/data
RUN mkdir -p /app/log && chown uconfigservice:uconfigservice /app/log

# Copiar los archivos de configuración
COPY --chown=uconfigservice:uconfigservice data /app/data

# Copiar el script de inicio y darle permisos de ejecución
COPY start.sh /start.sh
RUN chmod +x /start.sh

# Exponer el puerto 80 para Nginx
EXPOSE 80

# Usar el script de inicio como CMD
CMD ["/start.sh"]