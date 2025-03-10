-- Conectarse a la base de datos config_db
\c config_db;
-- Insertar datos de ejemplo en la tabla devices
INSERT INTO devices (name, device_type, config_file_path) VALUES
('switch_ml', 'switch', 'device_1.txt'),
('switch_sin_config_file', 'switch', 'device_2.txt'),
('firewall_no_soportado', 'firewall', 'device_3.txt');

-- Insertar usuario de prueba en la tabla users
INSERT INTO users (username, password_hash) VALUES
('uanalysis', '$2b$12$OL7Nu.3sXiuLPGxa2HMSR./rELbJ2fLWbliBWrKNl7qgPuQt5PFIa');

-- Conectarse a la base de datos analysis_db
\c analysis_db;
-- Insertar datos de ejemplo en la tabla users
INSERT INTO users (username, password_hash) VALUES
('analyst_test', '$2b$12$OL7Nu.3sXiuLPGxa2HMSR./rELbJ2fLWbliBWrKNl7qgPuQt5PFIa');

-- -- Insertar datos de ejemplo en la tabla reports
-- INSERT INTO reports (owner_id, result) VALUES
-- (1, 'Análisis de seguridad completado para el dispositivo 1'),
-- (2, 'Análisis de seguridad completado para el dispositivo 2');