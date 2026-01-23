-- Tenant unique PoC
-- On encode tenant_id directement dans les lignes (pas de table tenants pour garder simple)

-- Users (PoC) : password_hash = mot de passe en clair (à remplacer par bcrypt dans le backend si tu veux)
-- Identifiants :
-- - dev / dev
-- - agent / agent
-- - admin / admin
INSERT INTO users (tenant_id, username, role, password_hash)
VALUES
  ('t1', 'dev',   'developer', 'dev'),
  ('t1', 'agent', 'agent',     'agent'),
  ('t1', 'admin', 'admin',     'admin')
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
