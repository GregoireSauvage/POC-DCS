# Plan d'implementation securite auth (Backend / Frontend / Vault)

## 1) Contexte et objectif

Ce plan detaille l'implementation precise des 6 axes d'amelioration:

1. Auth utilisateur (hash + hygiene credentials)
2. Transport (TLS)
3. Session web (cookie HttpOnly)
4. Auth backend -> Vault (token dynamique)
5. Durcissement controle d'acces
6. Cycle de vie token (refresh / revocation / rotation cle)

Le scope couvre le repo actuel:
- backend FastAPI
- frontend React
- nginx
- Vault
- docker compose / scripts d'init


## 2) Sequencement recommande

Ordre conseille pour minimiser le risque:

- Phase A: (1) + (5)
- Phase B: (2)
- Phase C: (3)
- Phase D: (4)
- Phase E: (6)

Raison:
- (1) et (5) donnent un gain securite rapide sans casser l'architecture.
- (2) est prerequis fort pour (3) en prod.
- (4) et (6) demandent plus de changements transverses.


## 3) Plan detaille par axe

## 3.1 Axe 1 - Auth utilisateur (hash mots de passe)

### Objectif
Supprimer tout mot de passe en clair et passer a un stockage robuste (Argon2id ou bcrypt).

### Implementation

1) Ajouter un module de hash:
- Nouveau fichier backend: `backend/app/core/security/passwords.py`
- Fonctions:
  - `hash_password(plain: str) -> str`
  - `verify_password(plain: str, hashed: str) -> bool`
- Algo recommande: `argon2-cffi` (sinon `passlib[bcrypt]` deja present).

2) Adapter login:
- Fichier: `backend/app/api/routers/auth.py`
- Remplacer:
  - `user.password_hash != payload.password`
  - par `not verify_password(payload.password, user.password_hash)`

3) Migration donnees:
- Alembic migration pour convertir les comptes seed.
- Option simple:
  - Regenerer seed avec hash pre-calcule
  - Ou script de migration qui hash les mots de passe existants.
- Fichiers impactes:
  - `infra/postgres/init/02_seed.sql`
  - `backend/alembic/...` (nouvelle revision)

4) Validation d'entree:
- Refuser mot de passe vide/court dans l'API login.

5) Tests:
- Unit tests `hash_password/verify_password`
- Test login succes/echec avec hash
- Test compat migration seed

### Criteres d'acceptance
- Aucun mot de passe en clair dans DB apres migration.
- Login fonctionne pour dev/agent/admin avec hash uniquement.
- Les tests backend auth passent.
- Recherche de pattern clair (`'dev'`, `'agent'`, `'admin'` en password column) renvoie 0 resultat.


## 3.2 Axe 2 - Transport TLS

### Objectif
Chiffrer tous les flux reseau sensibles.

### Implementation

1) HTTPS sur Nginx:
- Ajouter cert local dev (mkcert ou cert auto-signe) + config TLS.
- Fichier: `infra/nginx/nginx.conf`
- Redirection HTTP -> HTTPS.
- Headers securite:
  - `Strict-Transport-Security`
  - `X-Content-Type-Options`
  - `X-Frame-Options`
  - `Referrer-Policy`

2) TLS pour Vault:
- Fichier: `infra/vault/config/vault.hcl`
- Remplacer `tls_disable = 1` par config cert/key.
- Ajuster `VAULT_ADDR` en `https://...`:
  - `docker-compose.yml`
  - backend env
  - scripts init Vault.

3) Cert trust:
- Conteneur backend doit faire confiance au cert Vault.
- Ajouter CA trust store dans image backend si necessaire.

4) Tests:
- Test smoke HTTPS front->nginx->backend
- Test backend->Vault encrypt/decrypt en TLS

### Criteres d'acceptance
- Acces app via HTTPS uniquement.
- Vault API accessible uniquement en HTTPS.
- Aucun appel backend->Vault en HTTP clair.
- Les endpoints critiques (`/auth/login`, `/films/*`) fonctionnent en TLS.


## 3.3 Axe 3 - Session web via cookie HttpOnly

### Objectif
Sortir le JWT de `localStorage` et reduire risque d'exfiltration XSS.

### Implementation

1) Backend:
- `POST /auth/login`:
  - Set-Cookie `access_token` (HttpOnly, Secure, SameSite=Lax/Strict, Path=/)
  - Optionnel: cookie refresh separe.
- Ajouter endpoint `POST /auth/logout` pour invalider cookie.
- Adapter `get_current_principal`:
  - Priorite Authorization header
  - fallback cookie si header absent.

2) Frontend:
- Retirer stockage token dans `localStorage`:
  - `frontend/src/state/auth.tsx`
  - `frontend/src/api/client.ts`
- Passer `fetch(..., credentials: "include")`
- Stocker seulement meta session non sensible (role, username) ou recharger via `/auth/me`.

3) CORS/CSRF:
- `allow_origins` strict (pas `*`) et `allow_credentials=True`.
- Ajouter protection CSRF:
  - double-submit token ou header anti-CSRF pour requetes state-changing.

4) Tests:
- Test login pose bien les cookies securises.
- Test appel API authentifie sans token JS explicite.
- Test logout invalide session.

### Criteres d'acceptance
- Aucun JWT dans `localStorage`/`sessionStorage`.
- API fonctionne avec cookie HttpOnly.
- Requetes mutantes proteges CSRF.
- Flux login/logout valide sur UI.


## 3.4 Axe 4 - Auth backend -> Vault dynamique

### Objectif
Supprimer `VAULT_TOKEN` statique et utiliser une auth machine-to-machine a TTL court.

### Implementation

Option recommande (docker/simple): AppRole.

1) Vault:
- Creer role AppRole `backend`.
- Policy limitee:
  - `transit/encrypt/<key>`
  - `transit/decrypt/<key>`
  - `secret/data/dcs` (read)
- TTL court (ex 15m) + renewable.

2) Backend:
- Nouveau module auth Vault:
  - `backend/app/dcs/kms/vault_auth.py`
  - login AppRole (`role_id`, `secret_id`) -> `client_token`
  - refresh / re-login avant expiration.
- Modifier `VaultClient` pour obtenir token via provider dynamique au lieu de `settings.VAULT_TOKEN`.

3) Config:
- Nouvelles env vars:
  - `VAULT_AUTH_METHOD=approle`
  - `VAULT_ROLE_ID`
  - `VAULT_SECRET_ID`
- Retirer `VAULT_TOKEN` de `docker-compose.yml` (ou garder fallback dev explicite).

4) Rotation:
- Script ops pour rotate `secret_id` sans downtime.

5) Tests:
- Test login Vault AppRole OK.
- Test renouvellement token.
- Test refus si token expire et recovery auto.

### Criteres d'acceptance
- Backend n'utilise plus de token Vault statique en prod.
- Token Vault observe en runtime avec TTL court.
- Rotation `secret_id` possible sans redemarrage complet.
- Policy Vault reste minimale (least privilege).


## 3.5 Axe 5 - Durcissement controle d'acces

### Objectif
Reduire surface d'attaque sur login et endpoints sensibles.

### Implementation

1) Rate limit login:
- Limiter `/auth/login` (IP + username).
- Reponse 429 au depassement.
- Option: middleware rate-limit (Redis en prod; in-memory en dev).

2) Lockout progressif:
- N echecs consecutifs -> cooldown temporaire.
- Journaliser l'evenement.

3) Journalisation securite:
- Loguer tentatives login echec/succes avec request_id.
- Ajouter event type securite (auth_failed, auth_success, forbidden).

4) CORS strict:
- Dans `backend/app/main.py`, remplacer `allow_origins=["*"]` par whitelist.

5) Tests:
- Tests rate limit et lockout.
- Test CORS refus origine non autorisee.

### Criteres d'acceptance
- Bruteforce simple bloque (429/cooldown observable).
- Logs securite exploitables avec request_id.
- CORS wildcard supprime en env non-dev.
- Aucun endpoint admin accessible sans role admin (tests regression).


## 3.6 Axe 6 - Lifecycle token (refresh, revocation, rotation cle JWT)

### Objectif
Avoir une session robuste avec expiration courte + renouvellement controle.

### Implementation

1) Access/Refresh:
- Access token court (ex 5-15 min).
- Refresh token long (ex 7-30 jours), stocke HttpOnly Secure.
- Endpoint `POST /auth/refresh`.

2) Rotation refresh token:
- A chaque refresh:
  - nouveau refresh token
  - ancien invalide.

3) Revocation:
- Ajouter table `revoked_tokens` (jti, exp, reason) ou session table.
- Verifier `jti` a la validation.
- `POST /auth/logout` -> revoke refresh courant.

4) Rotation cle JWT:
- Introduire `kid` dans header JWT.
- Support multi-cles actives pendant transition.
- Source cles via secret manager (pas hardcode env unique).

5) Tests:
- Access expire -> refresh marche.
- Refresh reuse (token vole) detecte et bloque.
- Logout invalide refresh.
- Rotation cle ne casse pas tokens actifs durant fenetre de transition.

### Criteres d'acceptance
- Session reste fluide sans relogin frequent.
- Token vole reutilise est detecte (refresh rotation).
- Revocation effective en temps acceptable.
- Rotation cle JWT operationnelle sans interruption utilisateur.


## 4) Travaux transverses (obligatoires)

1) Documentation:
- Mettre a jour:
  - `README.md`
  - `docs/policies/README.md`
  - runbook ops (rotation secrets, rollback)

2) CI/CD:
- Ajouter jobs:
  - tests auth
  - tests integration TLS
  - tests Vault auth dynamique

3) Observabilite:
- Ajouter metriques:
  - login success/fail
  - refresh success/fail
  - vault auth success/fail/renew
  - rate limit hits

4) Feature flags de transition:
- Permettre migration progressive:
  - `AUTH_MODE=legacy|cookie`
  - `VAULT_AUTH_METHOD=static|approle`


## 5) Definition of Done globale

Le plan est considere termine quand:

- Les 6 axes sont implementes avec tests automatises verts.
- Plus aucun secret critique statique en clair dans compose dev/prod cible.
- Les flux auth (login, appel API, refresh, logout) sont verifies en e2e.
- Les operations de rotation (JWT keys, Vault creds) sont documentees et testees.
- Une revue securite finale valide les criteres d'acceptance de chaque axe.

