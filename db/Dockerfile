FROM postgres:13

# Copiar el script de inicialización unificado
EXPOSE 5432

COPY init.sql /docker-entrypoint-initdb.d/init.sql
COPY setusers.sh /docker-entrypoint-initdb.d/setusers.sh
RUN chmod +x /docker-entrypoint-initdb.d/setusers.sh