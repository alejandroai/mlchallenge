-- Crear la base de datos config_db
CREATE DATABASE config_db;
CREATE DATABASE analysis_db;
--- Crear los usuarios con accesos a la db
CREATE USER uconfig WITH PASSWORD 'iwtwxxFJo4y2etDBzeRk';
CREATE USER uanalysis WITH PASSWORD 'UJ3YHQbdRi1hiUbl1GDZ';

-- Dar permiso de conexion a los usuarios
GRANT CONNECT ON DATABASE config_db TO uconfig;
GRANT CONNECT ON DATABASE analysis_db TO uanalysis;

-- Conectarse a la base de datos config_db
\c config_db;
-- Crear la tabla devices
CREATE TABLE devices (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    device_type VARCHAR(50) NOT NULL,
    config_file_path VARCHAR(255) NOT NULL
);

-- Crear la tabla users
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL
);

-- Permisos de user de app (solo lectura)
GRANT SELECT ON ALL TABLES IN SCHEMA public TO uconfig;

-- Conectarse a la base de datos analysis_db
\c analysis_db;

-- Crear la tabla users
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL
);


-- Crear la tabla reports
CREATE TABLE reports (
    id SERIAL PRIMARY KEY,
    owner_id INT REFERENCES users(id) ON DELETE NO ACTION,
    result TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Permisos de user de app
GRANT SELECT ON ALL TABLES IN SCHEMA public TO uanalysis;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE reports TO uanalysis;
GRANT USAGE, SELECT ON SEQUENCE reports_id_seq TO uanalysis;