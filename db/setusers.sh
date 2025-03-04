#!/bin/bash

# Verificar si las variables de entorno están definidas
if [[ -z "${UCONFIG_PASSWORD}" || -z "${UANALYSIS_PASSWORD}" ]]; then
    echo "Error: Las variables de entorno UCONFIG_PASSWORD y UANALYSIS_PASSWORD deben estar definidas."
    exit 1
fi

# Conectar a PostgreSQL y actualizar las contraseñas
psql -U admin <<EOF
ALTER USER uconfig WITH PASSWORD '${UCONFIG_PASSWORD}';
ALTER USER uanalysis WITH PASSWORD '${UANALYSIS_PASSWORD}';
EOF

# Verificar si el comando anterior tuvo éxito
if [[ $? -eq 0 ]]; then
    echo "Contraseñas actualizadas correctamente."
else
    echo "Error al actualizar las contraseñas."
    exit 1
fi
