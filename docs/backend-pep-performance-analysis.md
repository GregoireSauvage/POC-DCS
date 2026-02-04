# Analyse des performances Backend/PEP (DCS & Caching)

## 1) Périmètre

Ce document décrit l'analyse des performances côté backend, avec un focus sur le **PEP** (Policy Enforcement Point) et la chaîne DCS:

- **PIP**: collecte des attributs (`app/dcs/pip/provider.py`)
- **PDP**: décision d'accès (`app/dcs/pdp/engine.py`, `app/dcs/pdp/policies.py`)
- **PEP**: application des décisions (decrypt/mask/deny) (`app/dcs/pep/data_pep.py`)
- **KMS**: Vault Transit pour decrypt/encrypt (`app/dcs/kms/vault_transit.py`)
- **Observabilité**: middleware, spans, persistance en DB (`app/observability/*`, `app/services/perf_service.py`)


## 2) Modes de fonctionnement DCS

Le mode runtime est piloté par `dcs_mode` (`app/core/runtime_settings.py`) et lu via `dcs_enabled()` (`app/dcs/pep/mode.py`).

### DCS ON
- Le backend évalue les politiques (`evaluate()`).
- Le PEP applique les actions par champ:
  - `decrypt`
  - `mask_after_decrypt`
  - `deny`
- Les champs chiffrés sont déchiffrés via Vault (`vault.decrypt`).

### DCS OFF
- Le PDP court-circuite les règles ABAC détaillées et applique un allow simplifié par action/rôle (`allow_without_dcs`).
- Le PEP ne déchiffre pas: il renvoie les valeurs brutes des colonnes ciphertext pour les champs sensibles (`apply_decision`, branche `if not dcs_enabled()`).
- Intérêt perf: suppression du coût de décision détaillée + suppression du coût KMS decrypt.


## 3) Niveaux de cache existants (backend)

Les caches sont en mémoire process, TTL, thread-safe (`app/cache/cache.py`).

### Vue d'ensemble

| Niveau | Activé si `CACHE_LEVEL >=` | Ce qui est mit en cache | Où |
|---|---:|---|---|
| L0 | 0 | Aucun cache DCS | - |
| L1 | 1 | Classification PIP + pepper KMS | `classification_cache`, `pepper_cache` |
| L2 | 2 | L1 + décisions PDP (seulement `film.read`, `film.update_time`) | `pdp_cache` |
| L3 | 3 | L2 + résultats decrypt KMS (ciphertext -> plaintext) | `kms_cache` |

### Détail implémentation

- **Classification cache (L1)**  
  - Clé: `resource_type`  
  - Valeur: `dict[field_name -> classification]`  
  - Code: `app/dcs/pip/classification.py`

- **Pepper cache (L1)**  
  - Clé fixe: `"pepper"`  
  - Valeur: `bytes`  
  - Code: `VaultClient.get_pepper()` (`app/dcs/kms/vault_transit.py`)

- **PDP decision cache (L2)**  
  - Activé pour `film.read` et `film.update_time` uniquement  
  - Clé riche: `dcs_enabled`, action, tenant, role, user, owner, labels, signature des classifications (`_decision_cache_key`)  
  - Code: `app/dcs/pdp/engine.py`

- **KMS decrypt cache (L3)**  
  - Clé: ciphertext complet  
  - Valeur: plaintext déchiffré  
  - Code: `VaultClient.decrypt()` (`app/dcs/kms/vault_transit.py`)

### Invalidations

- Changement runtime `dcs_mode` ou `cache_level` via `/admin/settings` -> `clear_all_caches()` automatique (`set_runtime_settings`).
- Expiration naturelle par TTL.


## 4) Stratégie de logging/perf

## 4.1 Instrumentation par requête

- `PerfMiddleware` crée un `PerfContext` par requête et ajoute le header `x-perf-total-ms`.
- `RequestIdMiddleware` ajoute/propague `x-request-id`.

## 4.2 Mesures détaillées

- **`pip_ms`** via `perf_span("pip_ms")` dans `build_policy_input`.
- **`pdp_ms`** via `perf_span("pdp_ms")` dans `evaluate`.
- **`kms_ms`** via `perf_span("kms_ms")` dans `VaultClient` (encrypt/decrypt/get_pepper).
- **`db_ms`** via hooks SQLAlchemy `before_cursor_execute` / `after_cursor_execute` (`app/db/session.py`).

## 4.3 Persistance

Le service `write_perf()` écrit dans `perf_logs`:
- contexte métier: tenant, user, role, action, resource_type
- contexte exécution: `dcs_enabled`, `cache_level`
- timings: `total_ms`, `pip_ms`, `pdp_ms`, `kms_ms`, `db_ms`

Exposition API:
- `GET /perf/` (logs bruts)
- `GET /perf/summary` (agrégats moyens par action / dcs / cache_level)


## 5) Comment comparer correctement les modes

Pour comparer proprement:

1. Choisir une action stable (ex: `film.read`, `film.update_time`).
2. Fixer un scénario de charge identique (RPS, durée, dataset).
3. Tester:
   - DCS OFF + L0..L3
   - DCS ON + L0..L3
4. Comparer `avg_total_ms`, puis `pdp_ms`, `kms_ms`, `db_ms`.
5. Vider les biais:
   - warmup initial
   - mêmes données
   - mêmes conditions réseau/Vault

Attendu typique:
- DCS OFF < DCS ON (surtout sur `kms_ms`)
- L1 réduit coût PIP (classification + pepper)
- L2 réduit coût PDP sur actions ciblées
- L3 réduit fortement `kms_ms` sur lectures répétitives


## 6) Limites actuelles

## 6.1 Limites de mesure

- `pip_ms` ne couvre pas toute la fonction `build_policy_input` (actuellement la span est partielle), donc peut sous-estimer le coût réel PIP.
- `db_ms` agrège toutes les requêtes SQL de la requête HTTP, y compris audit/perf logs, ce qui mélange coût métier et coût observabilité.
- `total_ms` inclut le pipeline complet HTTP backend (pas uniquement PEP pur).

## 6.2 Limites architecture cache

- Caches **in-memory, par process**:
  - pas partagés entre instances
  - perdus au restart
  - comportement non homogène en multi-réplicas
- Politique d'éviction simple (suppression arbitraire), pas LRU.
- Pas de métriques de hit/miss cache exposées actuellement.

## 6.3 Limites sécurité (à assumer explicitement)

- L3 garde du plaintext déchiffré en mémoire process (`kms_cache`): gain perf fort mais surface mémoire plus sensible.
- `pepper_cache` conserve le secret pepper en mémoire process.
- Le compromis perf/sécurité doit être validé selon l'environnement (PoC vs prod).


## 7) Recommandations concrètes (backend/PEP)

1. **Corriger la couverture `pip_ms`** pour englober l'ensemble de `build_policy_input`.
2. **Ajouter des compteurs de cache** (hit/miss par cache) dans `perf_logs` ou un endpoint dédié.
3. **Dissocier DB métier vs DB observabilité** (deux métriques) pour des analyses plus fiables.
4. **Rendre les actions cacheables configurables** (au lieu de hardcode `film.read` / `film.update_time`).
5. **Documenter un profil de sécurité par niveau de cache** (L0/L1/L2/L3) pour cadrer les usages.


## 8) Références code

- Mode runtime: `app/core/runtime_settings.py`
- DCS mode switch: `app/dcs/pep/mode.py`
- PIP: `app/dcs/pip/provider.py`, `app/dcs/pip/classification.py`
- PDP: `app/dcs/pdp/engine.py`, `app/dcs/pdp/policies.py`
- PEP: `app/dcs/pep/data_pep.py`
- KMS + cache decrypt/pepper: `app/dcs/kms/vault_transit.py`
- Cache infra: `app/cache/cache.py`
- Perf context/middleware: `app/observability/perf.py`, `app/observability/middleware.py`
- DB timing hooks: `app/db/session.py`
- Perf persistence: `app/services/perf_service.py`, `app/db/models/perf_log.py`
- API perf/admin: `app/api/routers/perf.py`, `app/api/routers/admin.py`
