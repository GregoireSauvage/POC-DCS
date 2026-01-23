-- infra/postgres/init/001_init.sql
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ---------- USERS ----------
CREATE TABLE IF NOT EXISTS users (
  tenant_id     TEXT NOT NULL,
  id            UUID NOT NULL DEFAULT gen_random_uuid(),
  username      TEXT NOT NULL,
  role          TEXT NOT NULL CHECK (role IN ('developer','agent','admin')),
  password_hash TEXT NOT NULL, -- PoC: peut être un hash ou un placeholder (voir seed)
  labels        JSONB NOT NULL DEFAULT '[]'::jsonb,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, username)
);

-- ---------- FILMS ----------
CREATE TABLE IF NOT EXISTS films (
  tenant_id           TEXT NOT NULL,
  id                  UUID NOT NULL DEFAULT gen_random_uuid(),
  title               TEXT NOT NULL,
  time_elapsed_ct     TEXT NOT NULL,      -- ciphertext Vault (plaintext: int/string)
  labels              JSONB NOT NULL DEFAULT '[]'::jsonb,
  created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id)
);

-- ---------- HALLS ----------
CREATE TABLE IF NOT EXISTS halls (
  tenant_id        TEXT NOT NULL,
  id               UUID NOT NULL DEFAULT gen_random_uuid(),
  name             TEXT NOT NULL,
  owner_user_id    UUID NOT NULL,
  current_film_id  UUID NOT NULL,
  labels           JSONB NOT NULL DEFAULT '[]'::jsonb,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, owner_user_id) REFERENCES users(tenant_id, id),
  FOREIGN KEY (tenant_id, current_film_id) REFERENCES films(tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_halls_owner ON halls(tenant_id, owner_user_id);

-- ---------- SPECTATORS ----------
CREATE TABLE IF NOT EXISTS spectators (
  tenant_id            TEXT NOT NULL,
  id                   UUID NOT NULL DEFAULT gen_random_uuid(), -- id interne
  hall_id              UUID NOT NULL,
  name_ct              TEXT NOT NULL,      -- ciphertext Vault
  age_ct               TEXT NOT NULL,      -- ciphertext Vault (plaintext: int)
  external_id_ct       TEXT NOT NULL,      -- ciphertext Vault
  external_id_lookup   BYTEA NOT NULL,     -- HMAC(pepper, normalize(external_id))
  labels               JSONB NOT NULL DEFAULT '[]'::jsonb,
  created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, hall_id) REFERENCES halls(tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_spectators_hall ON spectators(tenant_id, hall_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_spectators_lookup ON spectators(tenant_id, external_id_lookup);

-- ---------- FIELD CLASSIFICATION ----------
CREATE TABLE IF NOT EXISTS field_classification (
  resource_type   TEXT NOT NULL,
  field_name      TEXT NOT NULL,
  classification  TEXT NOT NULL CHECK (classification IN ('PUBLIC','INTERNAL','PII','SENSITIVE')),
  PRIMARY KEY (resource_type, field_name)
);

-- ---------- AUDIT LOGS ----------
CREATE TABLE IF NOT EXISTS audit_logs (
  id               BIGSERIAL PRIMARY KEY,
  ts               TIMESTAMPTZ NOT NULL DEFAULT now(),
  request_id       TEXT NOT NULL,

  tenant_id        TEXT NOT NULL,
  subject_user_id  UUID,
  subject_role     TEXT,

  action           TEXT NOT NULL,    -- ex: "spectator.read", "film.update_time"
  resource_type    TEXT NOT NULL,    -- "film" | "hall" | "spectator"
  resource_id      UUID,

  outcome          TEXT NOT NULL CHECK (outcome IN ('allow','deny','error')),
  decision_hash    TEXT,

  fields_decrypted TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
  fields_masked    TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
  fields_denied    TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],

  details          JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_logs(ts);
CREATE INDEX IF NOT EXISTS idx_audit_req ON audit_logs(request_id);
