FROM postgres:13

EXPOSE 5432

COPY 01-init.sql /docker-entrypoint-initdb.d/01-init.sql
COPY 03-data-insert.sql /docker-entrypoint-initdb.d/02-data-insert.sql
COPY 02-setusers.sh /docker-entrypoint-initdb.d/03-setusers.sh
RUN chmod +x /docker-entrypoint-initdb.d/03-setusers.sh