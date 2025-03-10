# Usar una imagen base de Nginx
FROM nginx:alpine

# Copiar los archivos de las carpetas al servidor web
COPY . /usr/share/nginx/html/


# Exponer el puerto 8000
EXPOSE 8000

# Configurar Nginx para servir las páginas en el puerto 8000
RUN echo "server { \
    listen 8000; \
    server_name localhost; \
    location /config-swg/ { \
        alias /usr/share/nginx/html/config-swg/; \
        index index.html; \
    } \
    location /analysis-swg/ { \
        alias /usr/share/nginx/html/analysis-swg/; \
        index index.html; \
    } \
}" > /etc/nginx/conf.d/default.conf

# Iniciar Nginx
CMD ["nginx", "-g", "daemon off;"]