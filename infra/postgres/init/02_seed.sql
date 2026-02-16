-- Tenant unique PoC
-- On encode tenant_id directement dans les lignes (pas de table tenants pour garder simple)

-- Users (PoC) : password_hash = bcrypt
-- Identifiants (passwords en clair) :
-- - dev / dev
-- - agent / agent
-- - admin / admin
INSERT INTO users (tenant_id, username, role, password_hash)
VALUES
  ('t1', 'dev',   'developer', '$2a$10$jceEtr.XLBzMomrUQzi/rOAa9ZA4yKk924IGPd3LjY7qSPzzaGJ4O'),
  ('t1', 'agent', 'agent',     '$2a$10$Ui2tT/lQp6zt9QVmXslinO7KoLTLqFDgWvLS27xqZCVAl.VBbWCUy'),
  ('t1', 'admin', 'admin',     '$2a$10$xPqTWNl/zQGqZz1X9/IphOPy/yf5hyBpU79SOe.y4KI9pekAz1Ovm')
ON CONFLICT (tenant_id, username) DO NOTHING;

-- Field classification
INSERT INTO field_classification(resource_type, field_name, classification) VALUES
('film', 'title', 'PUBLIC'),
('film', 'time_elapsed', 'SENSITIVE'),

('hall', 'name', 'PUBLIC'),
('hall', 'owner_user_id', 'INTERNAL'),
('hall', 'current_film_id', 'INTERNAL'),

('spectator', 'name', 'PII'),
('spectator', 'age', 'SENSITIVE'),
('spectator', 'external_id', 'PII')
ON CONFLICT (resource_type, field_name) DO NOTHING;
