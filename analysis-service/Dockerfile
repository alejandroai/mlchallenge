FROM python:3.9-slim

# Crear un usuario y grupo sin privilegios
RUN groupadd -r uanalysisservice && useradd -r -g uanalysisservice uanalysisservice
RUN apt-get update && apt-get install -y procps nginx

# Crear los directorios que Nginx necesita y asignar permisos
RUN mkdir -p /var/lib/nginx /var/log/nginx /var/cache/nginx /var/run/nginx && \
    chown -R uanalysisservice:uanalysisservice /var/lib/nginx /var/log/nginx /var/cache/nginx /var/run/nginx

# Crear el directorio de la aplicación
WORKDIR /app

# Copiar los archivos de requisitos e instalar dependencias
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar el código de la aplicación
COPY . .

# Crear la carpeta log si no existe
RUN mkdir -p /app/log && chown uanalysisservice:uanalysisservice /app/log

# Configurar Nginx
COPY nginx.conf /etc/nginx/nginx.conf

# Copiar el script de inicio y darle permisos de ejecución
COPY start.sh /start.sh
RUN chmod +x /start.sh

# Exponer el puerto 80 para Nginx
EXPOSE 80

# Usar el script de inicio como CMD
CMD ["/start.sh"]