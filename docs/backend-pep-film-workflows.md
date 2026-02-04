# Backend PEP workflows: `film.read` and `film.update_time`

## 1) Goal

This document explains, step by step, the backend workflow for:

- `film.read` (`GET /films`)
- `film.update_time` (`PATCH /films/{film_id}/time`)

Focus is on:

- payloads used at each stage (PIP -> PDP -> PEP -> logs)
- what each cache stores (or does not store)
- differences between DCS mode `on` and `off`

Source references:

- `backend/app/api/routers/films.py`
- `backend/app/dcs/pip/provider.py`
- `backend/app/dcs/pdp/engine.py`
- `backend/app/dcs/pep/data_pep.py`
- `backend/app/dcs/kms/vault_transit.py`
- `backend/app/cache/cache.py`
- `backend/app/services/cinema_service.py`


## 2) Baseline data model and classifications (film)

DB model (`films`):

- `tenant_id`
- `id`
- `title` (clear text)
- `time_elapsed_ct` (ciphertext)

Field classifications seeded in DB (`infra/postgres/init/02_seed.sql`):

- `film.title` -> `PUBLIC`
- `film.time_elapsed` -> `SENSITIVE`

So for film payloads, only `time_elapsed` goes through decrypt/mask logic.


## 3) Cache layers relevant to film flows

From `backend/app/cache/cache.py`:

- L1 (`CACHE_LEVEL >= 1`)
  - `classification_cache`: `resource_type -> classification map`
- L2 (`CACHE_LEVEL >= 2`)
  - `pdp_cache`: decision cache (only for `film.read` and `film.update_time`)
- L3 (`CACHE_LEVEL >= 3`)
  - `kms_cache`: decrypt cache `ciphertext -> plaintext`

Not used by film flows:

- `pepper_cache` (used by spectator lookup/encryptable search, not by film.read/update_time)


## 4) Workflow A: `film.read`

Endpoint: `GET /films`

### Step A1 - Request enters backend

Middlewares set:

- `request.state.request_id`
- `request.state.perf` (`PerfContext`)

No cache read/write here.

### Step A2 - Query film rows

Router executes:

```python
films = db.query(Film).filter(Film.tenant_id == p.tenant_id).all()
```

Payload at this stage (per row):

```json
{
  "id": "UUID",
  "title": "Interstellar",
  "time_elapsed_ct": "vault:v1:...."
}
```

No cache read/write here.

### Step A3 - Build policy input (PIP) for each row

`build_policy_input(... action="film.read", resource_type="film", crypto_meta={"time_elapsed": {"ciphertext_field": "time_elapsed_ct"}})`

Resulting `PolicyInput` shape:

```json
{
  "subject": {
    "user_id": "UUID-as-string",
    "tenant_id": "t1",
    "role": "admin|agent|developer",
    "username": "..."
  },
  "action": "film.read",
  "resource": {
    "type": "film",
    "id": "film-uuid",
    "owner_id": null,
    "tenant_id": "t1",
    "labels": [],
    "fields": {
      "title": {"classification": "PUBLIC"},
      "time_elapsed": {
        "classification": "SENSITIVE",
        "crypto": {"ciphertext_field": "time_elapsed_ct"}
      }
    }
  },
  "context": {
    "env": "dev|...",
    "channel": "web",
    "purpose": "cinema_ops",
    "client_ip": "...",
    "device_trust": 0.8,
    "request_id": "..."
  }
}
```

Cache behavior:

- DCS `on`:
  - L1: `classification_cache` may be read/written
    - key: `"film"`
    - value:
      ```json
      {"title": "PUBLIC", "time_elapsed": "SENSITIVE"}
      ```
- DCS `off`:
  - PIP exits early with `fields={}` (classification cache not used)

### Step A4 - Evaluate policy (PDP)

`evaluate(policy_input)`

Decision examples:

```json
// admin + DCS on
{
  "allow": true,
  "field_actions": {"title": "allow", "time_elapsed": "decrypt"},
  "reason": "read_allowed"
}
```

```json
// developer + DCS on
{
  "allow": true,
  "field_actions": {"title": "allow", "time_elapsed": "mask_after_decrypt"},
  "reason": "read_allowed"
}
```

```json
// any role allowed for read + DCS off
{
  "allow": true,
  "field_actions": {},
  "reason": "dcs_off"
}
```

Cache behavior:

- L2 enabled and action cacheable (`film.read`):
  - `pdp_cache` read by computed tuple key
  - miss -> decision computed and stored
  - value stored is a `Decision` object
- DCS off still uses L2 cache (decision is simple `dcs_off`)

### Step A5 - Apply decision (PEP)

Input to PEP:

```json
{
  "ciphertext_row": {
    "title": "Interstellar",
    "time_elapsed_ct": "vault:v1:...."
  },
  "field_to_ciphertext": {
    "time_elapsed": "time_elapsed_ct"
  }
}
```

PEP behavior:

- DCS `on`, `time_elapsed=decrypt`:
  - calls `vault.decrypt(time_elapsed_ct)`
  - returns `time_elapsed` as int when possible
- DCS `on`, `time_elapsed=mask_after_decrypt`:
  - decrypts first, then masks
- DCS `off`:
  - no decrypt
  - maps ciphertext directly to output field (`time_elapsed = time_elapsed_ct`)

Cache behavior:

- L3 enabled:
  - `kms_cache` key: ciphertext string
  - value: plaintext string (example `"120"`)
  - hit avoids Vault call
- L0/L1/L2: no decrypt cache

### Step A6 - Response + logs

Response per row:

```json
{
  "id": "film-uuid",
  "title": "Interstellar",
  "time_elapsed": 120
}
```

or masked/ciphertext depending on role + DCS mode.

Audit log (`audit_logs`) includes:

- action `film.read`
- outcome allow/deny
- fields decrypted/masked/denied

Perf log (`perf_logs`) includes:

- action `film.read`
- `dcs_enabled`, `cache_level`
- timings (`total_ms`, `pip_ms`, `pdp_ms`, `kms_ms`, `db_ms`)


## 5) Workflow B: `film.update_time`

Endpoint: `PATCH /films/{film_id}/time?time_elapsed=<int>`

Important: this endpoint has 2 policy phases:

1) authorize write (`film.update_time`)
2) format response under read policy (`film.read`)

### Step B1 - Request payload

Incoming payload:

```json
{
  "film_id": "UUID in path",
  "time_elapsed": 240
}
```

No cache read/write yet.

### Step B2 - PIP/PDP for write authorization (`film.update_time`)

PIP builds `PolicyInput` like film.read but with:

- `action="film.update_time"`
- `resource.id=<film_id>`

Decision examples:

```json
// agent/admin + DCS on
{
  "allow": true,
  "field_actions": {"title": "allow", "time_elapsed": "decrypt"},
  "reason": "write_allowed"
}
```

```json
// developer + DCS on
{
  "allow": false,
  "field_actions": {},
  "reason": "write_forbidden"
}
```

```json
// DCS off, developer
{
  "allow": false,
  "field_actions": {},
  "reason": "dcs_off"
}
```

Cache behavior:

- L1: classification cache can be read/written (`"film"`)
- L2: `pdp_cache` key for action `film.update_time` may hit/miss/store
- L3: not used yet (no decrypt in this step)

If deny:

- writes audit + perf
- returns 403

### Step B3 - Write operation (business service)

On allow, router calls:

`update_film_time(db, tenant_id, film_id, time_elapsed)`

Service behavior:

- loads film row
- encrypts new time with Vault:
  - `vault.encrypt(str(time_elapsed))`
- stores new ciphertext into `film.time_elapsed_ct`
- commit + refresh

Payload entering encrypt:

```json
{"plaintext": "240"}
```

Vault request payload:

```json
{"plaintext": "MjQw"} 
```

(`240` in base64)

Cache behavior:

- none for `encrypt` (no encrypt cache in current code)
- L3 only caches decrypt, not encrypt

### Step B4 - PIP/PDP again for response shaping (`film.read`)

After write, endpoint builds a new `PolicyInput` with action `film.read` for the updated row.

Cache behavior:

- L1: classification likely hit (`"film"`) if already loaded in B2
- L2: separate cache key for action `film.read` (distinct from `film.update_time`)

### Step B5 - PEP applies read decision to updated ciphertext

PEP input row:

```json
{
  "title": "Interstellar",
  "time_elapsed_ct": "vault:v1:new-ciphertext"
}
```

Cache behavior for decrypt:

- L3 checks `kms_cache[new-ciphertext]`
- usually miss for monotonic updates (new ciphertext each update)
- then Vault decrypt call, and value cached under this new ciphertext

Important practical effect:

- For repeated update_time tests that always produce new values, L3 helps little on this path.
- For repeated reads of unchanged rows, L3 can help a lot.

### Step B6 - Response + logs

Response:

```json
{
  "id": "film-uuid",
  "title": "Interstellar",
  "time_elapsed": 240
}
```

or masked/ciphertext depending on role + DCS mode.

Then:

- audit log for `film.update_time`
- perf log for `film.update_time`


## 6) Cache content summary by action

### `film.read`

- L1 `classification_cache["film"]`
  - stores only metadata (classifications), never plaintext film values
- L2 `pdp_cache[key(action=film.read,...)]`
  - stores `Decision` object (allow + field_actions + reason)
- L3 `kms_cache[ciphertext]`
  - stores decrypted plaintext string for `time_elapsed`

### `film.update_time`

- L1 `classification_cache["film"]`
  - same metadata as above
- L2 two possible entries in one request:
  - `key(action=film.update_time,...)`
  - `key(action=film.read,...)` (response shaping phase)
- L3:
  - no cache for encrypt
  - decrypt cache used only in response shaping phase
  - low hit rate when ciphertext changes every call


## 7) What is NOT cached in these two workflows

- SQL rows from `films` table are not cached in app code.
- Audit rows and perf rows are never cached (written directly to DB).
- JWT/principal is not cached in this path.
- Vault encrypt results are not cached.
- Pepper cache is not involved for film.read / film.update_time.


## 8) DCS off specifics (important)

When DCS is off:

- PIP returns `resource.fields={}` (classification lookup skipped)
- PDP returns coarse decision (`reason="dcs_off"`)
- PEP returns ciphertext for sensitive fields instead of decrypt/mask
- L2 can still cache PDP decisions
- L3 decrypt cache is effectively bypassed because decrypt is not called

