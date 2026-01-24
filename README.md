# Cinema DCS PoC — Présentation du projet

## 1) Objectif du PoC

Ce projet est un **PoC (proof of concept)** qui démontre une approche **Data-Centric Security (DCS)** cohérente avec **Zero Trust** dans une architecture “application web classique” :
- **Frontend web** (tests fonctionnels + changement d’utilisateur/role)
- **Gateway** (reverse-proxy + contrôle d’accès “entrée”)
- **Backend API** (logique métier + DCS “au plus près de la donnée”)
- **PostgreSQL** (données + métadonnées + audit)
- **KMS** (gestion crypto via Vault Transit)

Le but est de montrer concrètement :
- **Contrôle d’accès fin** *par champ* (allow / decrypt / mask / deny)
- **Chiffrement côté donnée** (pas “juste du réseau”)
- **Décisions pilotées par métadonnées** (classification, owner_id, tenant_id, labels, contexte)
- **Traçabilité** (audit des décisions et des champs touchés)

Référentiel conceptuel :
- **Zero Trust** : “pas de confiance implicite”, vérification + autorisation à chaque requête. (NIST SP 800‑207)
- **ABAC / points logiques PEP/PDP/PIP** : modèle “enforcement + décision + attributs”. (NIST SP 800‑162)
- **KMS Transit** : chiffrement “as a service”, les clés ne sortent pas du KMS. (Vault Transit docs)


## 2) Cas d’usage métier (cinéma)

On simule un système de suivi de projection :
- **Film** : `id`, `title`, `time_elapsed`
- **Hall (salle)** : `id`, `name`, `current_film_id`, `owner_user_id`, `spectator_count`
- **Spectator** : `id`, `hall_id`, `name`, `age`, `external_id` (ticket)

Rôles (3) :
- **developer** : lecture ok, mais données sensibles/PII **masquées**
- **agent** : lecture + écriture sur certaines ressources ; voit le “SENSITIVE” déchiffré ; la PII **masquée**
- **admin** : voit tout + accès audit

Classification (exemples) :
- `PUBLIC` : affichable sans crypto
- `INTERNAL` : masqué pour developer
- `SENSITIVE` : déchiffrable pour agent/admin
- `PII` : déchiffrable pour admin, **masquée** pour agent/dev


## 3) Architecture générale (vue d’ensemble)

```
[Browser]
   |
   | HTTPS (JWT)
   v
[Gateway / Nginx]  (PEP "entrée")
   |
   | /api/* (internal network)
   v
[Backend FastAPI]  (PEP "données")
   |   |    |   |  \--> [PIP] (facts/attributs)  (implémenté comme module aujourd’hui)
   |   \-----> [PDP] (décision)         (implémenté comme module aujourd’hui)
   |
   +--> [PostgreSQL] (données chiffrées + métadonnées + audit)
   |
   \--> [Vault Transit + KV] (PEP "clé" / KMS + pepper HMAC)
```

Points DCS :
- **PEP entrée** : la gateway valide/forward la requête (JWT, headers context, rate-limit si besoin).
- **PEP données** : le backend applique la décision *au moment où il sert la donnée*.
- **PIP** : assemble les **attributs** (subject/resource/context) nécessaires à la décision.
- **PDP** : calcule la **décision** (allow/deny + actions par champ).
- **PEP clé / KMS** : service crypto (Vault Transit) ; le backend appelle le KMS pour chiffrer/déchiffrer.

> Décision projet : pour rester simple au départ, **PIP/PDP sont aujourd’hui des modules dans le backend** (même container), mais **le design est “micro‑services ready”** (interfaces claires) pour les extraire ensuite en services dédiés.


## 4) Décisions DCS prises (et pourquoi)

### 4.1 Où se fait l’enforcement ?
- **Le vrai contrôle est côté backend**, au plus près de la donnée : c’est lui qui sait :
  - ce que contient la ressource (et ses métadonnées),
  - quels champs sont sensibles,
  - quoi déchiffrer/masquer/supprimer avant réponse.

Ça évite l’illusion “on a mis un WAF / un proxy donc c’est bon”. Ici le **PEP données** est le point dur.

### 4.2 Métadonnées “accrochées” aux données
Le DCS a besoin de métadonnées **persistées** et **fiables**, typiquement :
- `tenant_id` : séparation multi-tenant (frontière d’isolement forte)
- `owner_user_id` : propriété / responsabilité (utile pour policies du type “owner can see more”)
- `labels` : tags métier (ex: “minor”, “vip”, “internal-use”, “screening”)
- `field_classification` : classification des champs par type de ressource (Film/Hall/Spectator)
- audit : “qui a vu quoi”, “quels champs ont été déchiffrés/masqués/refusés”

### 4.3 Modèle de policy
On utilise une logique **ABAC simple** :
- subject : role, tenant, user_id
- resource : type, id, tenant, owner_id, labels, classification des champs
- context : endpoint/action, timestamp, etc.

Le PDP renvoie une décision :
- `allow` / `deny`
- et pour chaque champ : `allow` / `decrypt` / `mask_after_decrypt` / `deny`

C’est **beaucoup plus démonstratif** qu’un RBAC “tout ou rien” et colle mieux au DCS.

### 4.4 Chiffrement : choix actuel vs cible

**Choix actuel (PoC, simple)**  
- Les champs sensibles sont stockés en **ciphertext** dans Postgres.
- Le backend chiffre/déchiffre via **Vault Transit** (encryption-as-a-service).
- Les clés ne sortent pas du KMS.

**Choix cible (plus “pur” DCS, maturité +)**  
- Passer à de l’**envelope encryption** :
  - DEK par “objet” (ou par champ/catégorie) pour chiffrer localement
  - DEK chiffrée (wrapped) par une KEK dans le KMS
  - rotation plus simple + perf meilleure (moins d’allers-retours KMS)

Le PoC démarre simple, puis on peut itérer vers l’envelope sans casser l’architecture.

### 4.5 Recherche SQL sur donnée chiffrée (cas utile)
Pour `Spectator.external_id` (ticket) :
- on chiffre le ticket (`external_id_ct`) pour la confidentialité,
- et on stocke un **HMAC** (`external_id_lookup`) pour permettre une recherche exacte (`WHERE external_id_lookup = ...`) sans stocker le ticket en clair.

La clé de HMAC (“pepper”) est stockée dans **Vault KV** et jamais en DB.


## 5) Schéma de données (vue logique)

Tables principales :
- `users` : utilisateurs seedés (dev/agent/admin) + tenant
- `films` : `time_elapsed_ct` chiffré + `labels`
- `halls` : `current_film_id`, `owner_user_id`, `labels`
- `spectators` : `name_ct`, `age_ct`, `external_id_ct` + `external_id_lookup` (HMAC) + `labels`
- `field_classification` : mapping `{resource_type, field_name -> classification}`
- `audit_log` : événements d’enforcement (allow/deny + champs decrypt/mask/deny + request_id)

Ce que le PoC montre bien :
- les champs “sensibles” existent **uniquement chiffrés** en base,
- l’autorisation est **décorrélée** du transport (le réseau n’est pas “le contrôle”),
- l’audit révèle le comportement du PEP/PDP sans exposer la donnée.


## 6) Choix technos (et rationalité)

- **Frontend** : React + TypeScript + Vite  
  Objectif : UI simple, rapide à itérer, changement d’utilisateur en 1 clic.
- **Gateway** : Nginx  
  Objectif : reverse-proxy, routage `/api`, couche “entry PEP” minimale.
- **Backend** : Python FastAPI + Pydantic + SQLAlchemy  
  Objectif : productif, typage, validation, clean arch minimale.
- **DB** : PostgreSQL  
  Objectif : relationnel, index, JSONB/UUID, contraintes fortes.
- **KMS** : HashiCorp Vault (Transit + KV)  
  Objectif : crypto “as a service”, clés hors app, pepper HMAC hors DB.
- **Packaging/Run** : Docker Compose  
  Objectif : PoC reproductible sous Windows 11 / WSL2 / Linux.
- **Python deps** : `uv`  
  Objectif : install/sync rapide et reproductible via `uv.lock`.


## 7) État du projet (à date)

✅ Fonctionnel :
- dockerisation frontend/backend + run via compose
- authentification JWT (login dev/agent/admin)
- endpoints métier : films, halls, spectators, audit
- chiffrement/déchiffrement via Vault Transit
- classification par champ via table `field_classification`
- décision PDP par action + classification + rôle
- enforcement PEP : decrypt / mask / deny par champ
- recherche spectator par ticket via HMAC lookup
- UI améliorée (lisible + explicite)

⚠️ Limites assumées du PoC :
- PIP/PDP dans le backend (pas encore des services séparés)
- chiffrement direct via KMS (pas encore envelope encryption)
- authN/authZ simplifiés (seed users, pas d’IdP, pas de rotation JWT)
- réseau “minimal” (pas mTLS, pas d’attestation device)
- policies “policy-as-code” dans le repo (pas de PAP dédié ni workflow de déploiement des politiques)


## 8) Prochaines étapes (maturité 4 “raisonnable”)

1) **Envelope encryption**
   - génération DEK par ressource (ou catégorie)
   - DEK wrapped par KEK Vault
   - rotation KEK/DEK + rewrap

2) **Sortir PIP et PDP en services dédiés**
   - PIP : agrégation attributs (DB + sources externes)
   - PDP : moteur de décision (OPA/Rego, Cedar, XACML-like, ou policy-as-code versionnée)

3) **Renforcer Zero Trust**
   - identité service-to-service (mTLS, SPIFFE/SPIRE ou équivalent)
   - tokens Vault par service (AppRole/Kubernetes auth)
   - segmentation réseau stricte + deny-by-default

4) **Observabilité & contrôle**
   - audit enrichi (correlation id, latence décision, taux deny)
   - dashboards + alerting sur anomalies (ex: “trop de decrypts”)
   - tests de policies (unit tests PDP, golden tests PEP)

5) **Performance**
   - cache décision court-terme côté PEP (avec invalidation)
   - batch decrypt si nécessaire (limiter appels KMS)
   - stratégies streaming (masquage sans déchiffrer si possible)


## 9) Comment lire ce PoC (ce qui est important)

- Le DCS n’est pas “un produit”, c’est une **manière de structurer la sécurité autour de la donnée** :
  - classification + labels + metadata,
  - décisions explicites,
  - enforcement près de la donnée,
  - chiffrement + KMS,
  - audit systématique.

- Zero Trust ici est “pragmatique” :
  - vérification JWT + décision par requête,
  - pas de confiance implicite “réseau interne”,
  - séparation des rôles et des champs.

---

## Références (base conceptuelle)
- NIST SP 800‑207 (Zero Trust Architecture)
- NIST SP 800‑162 (ABAC : PDP/PEP/PIP et modèle attributs)
- HashiCorp Vault Transit (docs + API)
