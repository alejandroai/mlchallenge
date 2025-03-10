#!/bin/bash
# Script para levantar Gunicorn (servidor WSGI) y Nginx

# Variables de configuración
APP_HOST="127.0.0.1"  # Dirección IP donde Gunicorn escuchará
APP_PORT="8080"       # Puerto donde Gunicorn escuchará

# Levantar la aplicación Flask con Gunicorn en segundo plano
echo "Iniciando la aplicación Flask con Gunicorn..."
gunicorn --bind $APP_HOST:$APP_PORT --workers 3 --threads 2 app:app &

# Esperar un momento para asegurarse de que Gunicorn esté listo
sleep 2

# Verificar si Gunicorn está en ejecución
if ! pgrep -x "gunicorn" > /dev/null; then
    echo "Error: Gunicorn no se ha iniciado correctamente."
    exit 1
fi

# Levantar Nginx en primer plano (necesario para que Docker no se cierre)
echo "Iniciando Nginx..."
nginx -g "daemon off;"