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

---

## 3) Benchmark de performances

Moyenne du temps de traitement total d'une requete pour l'ecriture et la lecture d'un film, pour chacun des deux backend et selon le niveau de cache + l'activation ou non du DCS. </br>
DCS off : on skip completement le DCS et on envoie directement les données chiffrées au client. </br>
### **film.read :**

|           	| **Backend Go** 	|                 	| **Backend Python** 	|                 	|
|:---------:	|:--------------:	|:---------------:	|:------------------:	|:---------------:	|
| **Cache** 	| **DCS on avg** 	| **DCS off avg** 	|   **DCS on avg**   	| **DCS off avg** 	|
| L0        	| 1.10 ms        	| 0.63 ms         	| 3.48 ms            	| 2.15 ms         	|
| L1        	| 1.05 ms        	| 0.63 ms         	| 3.20 ms            	| 2.17 ms         	|
| L2        	| 1.04 ms        	| 0.64 ms         	| 3.21 ms            	| 2.17 ms         	|
| L3        	| 0.65 ms        	| 0.64 ms         	| 2.19 ms            	| 2.20 ms         	|


### **film.update_time :**

|           	| **Backend Go** 	|                 	| **Backend Python** 	|                 	|
|:---------:	|:--------------:	|:---------------:	|:------------------:	|:---------------:	|
| **Cache** 	| **DCS on avg** 	| **DCS off avg** 	|   **DCS on avg**   	| **DCS off avg** 	|
| L0        	| 1.91 ms        	| 1.38 ms         	|       6.36 ms      	|     4.58 ms     	|
| L1        	| 1.75 ms        	| 1.38 ms         	|       5.76 ms      	|     4.54 ms     	|
| L2        	| 1.74 ms        	| 1.38 ms         	|       5.67 ms      	|     4.60 ms     	|
| L3        	| 1.74 ms        	| 1.38 ms         	|       5.71 ms      	|     4.55 ms     	|

---

## 4) Qu'est-ce que le Data-Centric Security (DCS) ?

### 4.1 Philosophie DCS

Le **Data-Centric Security** est une approche qui place **la donnée elle-même** au centre de la stratégie de sécurité, plutôt que le périmètre réseau ou les applications.

**Principes clés :**

1. **La donnée se protège elle-même** : chiffrement, classification, métadonnées de contrôle d'accès attachées à la donnée
2. **Protection indépendante du contexte** : la donnée reste protégée qu'elle soit au repos, en transit, ou en mémoire
3. **Granularité fine** : contrôle d'accès au niveau du champ, pas seulement de la ressource
4. **Décisions basées sur les attributs** : rôle + classification + contexte + propriété
5. **Audit complet** : traçabilité de qui accède à quoi, comment (decrypt/mask/deny)

**Différence avec l'approche traditionnelle :**

| Approche Traditionnelle | Approche DCS |
|------------------------|--------------|
| Périmètre réseau (firewall, VPN) | Protection attachée à la donnée |
| "Inside = trusted" | Zero Trust : vérification continue |
| RBAC tout-ou-rien (accès complet ou rien) | ABAC granulaire (decrypt/mask par champ) |
| Chiffrement en transit (TLS) | Chiffrement au repos + en transit + en mémoire |
| Audit "qui s'est connecté" | Audit "qui a vu quel champ, comment" |

### 4.2 Les 3 Piliers du DCS (PIP/PDP/PEP)

Le DCS s'appuie sur le modèle **ABAC (Attribute-Based Access Control)** défini par le NIST SP 800-162 :

```
┌─────────────────────────────────────────────────────────────┐
│                    REQUÊTE UTILISATEUR                       │
│          (Principal + Action + Resource + Context)           │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
            ┌────────────────────────┐
            │   PIP (Attribute)      │  ← Rassemble les attributs
            │  Policy Info Point     │     - User: role, tenant
            │                        │     - Resource: classification, owner
            │  "Qui es-tu ?"         │     - Context: IP, timestamp
            │  "C'est quoi la data ?"│
            │  "Quel contexte ?"     │
            └────────────┬───────────┘
                         │ PolicyInput (tous les attributs)
                         ▼
            ┌────────────────────────┐
            │   PDP (Decision)       │  ← Évalue la politique
            │  Policy Decision Point │
            │                        │     Entrée: PolicyInput
            │  "Autorisé ou pas ?"   │     Sortie: Decision {
            │  "Quels champs voir ?" │       allow: true/false
            │                        │       field_actions: {
            └────────────┬───────────┘         time_elapsed: "decrypt"
                         │                     age: "mask_after_decrypt"
                         │ Decision              name: "deny"
                         ▼                   }
            ┌────────────────────────┐     }
            │   PEP (Enforcement)    │  ← Applique la décision
            │  Policy Enforce Point  │
            │                        │     - Déchiffre (via KMS)
            │  "Application réelle"  │     - Masque (age → "+18")
            │  decrypt/mask/deny     │     - Supprime (deny)
            │                        │     - Audit (log décision)
            └────────────┬───────────┘
                         │ Données filtrées/masquées
                         ▼
            ┌────────────────────────┐
            │   RÉPONSE UTILISATEUR  │
            │  (données conformes    │
            │   à la décision)       │
            └────────────────────────┘
```

**Rôle de chaque composant :**

- **PIP (Policy Information Point)** : Collecteur d'attributs
  - Interroge la base de données pour les métadonnées (classification, owner_id, labels)
  - Extrait les attributs du principal (role, tenant, user_id)
  - Capture le contexte (action, IP, timestamp)
  - **Sortie** : `PolicyInput` complet

- **PDP (Policy Decision Point)** : Moteur de décision
  - Évalue les politiques (règles ABAC)
  - Croise les attributs : role × classification × ownership × context
  - **Sortie** : `Decision` avec actions par champ (allow/decrypt/mask/deny)

- **PEP (Policy Enforcement Point)** : Exécuteur
  - Applique la décision sur les données réelles
  - Appelle le KMS pour déchiffrer si autorisé
  - Masque les champs selon les règles (ex: age → "+18")
  - Supprime les champs "deny"
  - Logue l'audit (qui a vu quoi, comment)
  - **Sortie** : Réponse utilisateur filtrée

### 4.3 Architecture Globale du Système (Vue Complète)

Le PoC implémente deux backends en parallèle pour démonstration :

```
┌────────────────────────────────────────────────────────────────────────────────┐
│                              ARCHITECTURE GLOBALE                               │
└────────────────────────────────────────────────────────────────────────────────┘

                           ┌──────────────────┐
                           │     Browser      │
                           │  React + Vite    │
                           └────────┬─────────┘
                                    │ HTTPS (JWT in Authorization header)
                                    ▼
                           ┌──────────────────┐
                           │  Nginx Gateway   │  ← PEP "Entrée"
                           │  (Reverse Proxy) │    - Valide JWT
                           └────────┬─────────┘    - Rate limiting
                                    │              - Forwarding
                        ┌───────────┴───────────┐
                        │                       │
              /api/py/* │                       │ /api/go/*
                        ▼                       ▼
           ┌─────────────────────┐   ┌─────────────────────┐
           │  Backend Python     │   │  Backend Go         │
           │  (FastAPI)          │   │  (HTTP + gRPC)      │  ← PEP "Données"
           │                     │   │                     │
           │  ┌───────────────┐  │   │  ┌───────────────┐  │
           │  │ DCS Modules   │  │   │  │ DCS Enforcer  │  │
           │  │ - PIP         │  │   │  │ - PIP         │  │
           │  │ - PDP         │  │   │  │ - PDP         │  │
           │  │ - PEP         │  │   │  │ - PEP         │  │
           │  └───────────────┘  │   │  └───────────────┘  │
           └──────────┬──────────┘   └──────────┬──────────┘
                      │                         │
                      └──────────┬──────────────┘
                                 │
                 ┌───────────────┼───────────────┐
                 │               │               │
                 ▼               ▼               ▼
        ┌────────────────┐ ┌────────────┐ ┌──────────────┐
        │   PostgreSQL   │ │   Vault    │ │  Observability│
        │                │ │            │ │               │
        │ - films        │ │ - Transit  │ │ - Audit logs  │
        │ - halls        │ │   (KMS)    │ │ - Perf logs   │
        │ - spectators   │ │ - KV       │ │               │
        │ - users        │ │   (pepper) │ │               │
        │ - field_class  │ │            │ │               │
        │ - audit_log    │ │            │ │               │
        └────────────────┘ └────────────┘ └──────────────┘
              ▲                  ▲
              │                  │
              │ Métadonnées      │ Clés crypto
              │ + Audit          │ (Transit + pepper HMAC)
              │                  │
              └──────────────────┘
```

**Flux de données :**

1. **Browser** → Authentification JWT → **Nginx**
2. **Nginx** → Validation JWT → Forward vers **Backend Python** ou **Go**
3. **Backend** → Requête DB → **PostgreSQL** (données chiffrées)
4. **Backend** → PIP collecte attributs (user, resource classification, context)
5. **Backend** → PDP décide (allow/deny + actions par champ)
6. **Backend** → PEP applique :
   - **Vault** pour decrypt (si autorisé)
   - Masking local (si mask_after_decrypt)
   - Suppression (si deny)
7. **Backend** → Audit log → **PostgreSQL** (`audit_log` table)
8. **Backend** → Réponse filtrée → **Browser**

### 4.4 Architecture Détaillée : Backend Go (Hexagonal)

Le backend Go implémente une **architecture hexagonale (Ports & Adapters)** pour maximiser la testabilité et l'évolutivité.

#### Structure des couches

```
backend-go/
├── cmd/server/              # Point d'entrée (main)
├── internal/
│   ├── transport/           # PRIMARY ADAPTERS (driven by)
│   │   ├── http/            # HTTP handlers
│   │   └── grpc/            # gRPC handlers (futur)
│   │
│   ├── service/             # APPLICATION CORE (Use Cases)
│   │   ├── film_workflow.go
│   │   ├── hall_service.go
│   │   ├── spectator_service.go
│   │   ├── policy_enforcer.go  ← Interface (Port)
│   │   ├── audit_writer.go
│   │   └── perf_writer.go
│   │
│   ├── domain/              # ENTITIES (structs de données)
│   │   ├── cinema.go        # Film, Hall, Spectator
│   │   ├── user.go
│   │   ├── audit_log.go
│   │   └── perf_log.go
│   │
│   ├── dcs/                 # SECONDARY ADAPTERS (DCS orchestration)
│   │   ├── enforcer/        # Implémentation PolicyEnforcer
│   │   │   ├── film.go
│   │   │   ├── hall.go
│   │   │   └── spectator.go
│   │   ├── pip/             # Policy Information Point
│   │   ├── pdp/             # Policy Decision Point
│   │   ├── pep/             # Policy Enforcement Point
│   │   ├── kms/             # Key Management
│   │   ├── cache/           # Cache Manager
│   │   ├── runtime/         # Runtime settings
│   │   └── types/           # Types DCS partagés
│   │
│   ├── repository/          # SECONDARY ADAPTERS (Database)
│   │   ├── postgres/        # PostgreSQL implementation
│   │   └── memory/          # In-memory (dev/test)
│   │
│   ├── auth/                # JWT service
│   ├── config/              # Configuration
│   └── observability/       # Performance tracking
│
└── proto/                   # gRPC definitions (futur)
```

#### Diagramme Hexagonal

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        HEXAGONAL ARCHITECTURE                                │
│                         (Backend Go - DCS)                                   │
└─────────────────────────────────────────────────────────────────────────────┘

                    ┌────────────────────────────┐
                    │   PRIMARY ADAPTERS         │
                    │   (Infrastructure Entrée)  │
                    ├────────────────────────────┤
                    │  HTTP Handler              │
                    │  - /films  GET/POST        │
                    │  - /halls  GET/POST        │
                    │  - /spectators GET/POST    │
                    │                            │
                    │  gRPC Handler (futur)      │
                    │  - FilmService.List        │
                    │  - FilmService.Create      │
                    └──────────┬─────────────────┘
                               │
                               │ Appelle Use Cases
                               ▼
        ┌──────────────────────────────────────────────────────────┐
        │              APPLICATION CORE                             │
        │          (Business Logic - Domain)                        │
        ├──────────────────────────────────────────────────────────┤
        │                                                           │
        │  ┌─────────────────────────────────────────────────┐     │
        │  │  SERVICE LAYER (Use Cases)                      │     │
        │  │                                                 │     │
        │  │  FilmService {                                  │     │
        │  │    repo: FilmRepository       ← Port (interface)│     │
        │  │    enforcer: PolicyEnforcer   ← Port (interface)│     │
        │  │    audit: AuditWriter         ← Port (interface)│     │
        │  │    perf: PerfWriter           ← Port (interface)│     │
        │  │  }                                              │     │
        │  │                                                 │     │
        │  │  Methods:                                       │     │
        │  │  - Create(input) → FilmOutput                   │     │
        │  │  - List() → []FilmOutput                        │     │
        │  │  - UpdateTime(filmID, time)                     │     │
        │  └─────────────────────────────────────────────────┘     │
        │  Note: le service ne touche jamais au KMS.               │
        │  Le chiffrement/déchiffrement est géré par               │
        │  le DCS Enforcer (PIP/PDP/PEP).                          │
        │                                                           │
        │  ┌─────────────────────────────────────────────────┐     │
        │  │  DOMAIN LAYER (Entities)                        │     │
        │  │                                                 │     │
        │  │  type Film struct {                             │     │
        │  │    ID            string                         │     │
        │  │    TenantID      string                         │     │
        │  │    Title         string                         │     │
        │  │    TimeElapsedCT string  ← Chiffré             │     │
        │  │    Labels        []string                       │     │
        │  │    CreatedAt     time.Time                      │     │
        │  │  }                                              │     │
        │  └─────────────────────────────────────────────────┘     │
        │                                                           │
        └────────┬──────────────────────────────┬───────────────────┘
                 │                              │
                 │ Via Ports (Interfaces)       │
                 ▼                              ▼
   ┌─────────────────────────┐      ┌──────────────────────────┐
   │  SECONDARY ADAPTERS     │      │  SECONDARY ADAPTERS      │
   │  (Infrastructure Sortie)│      │  (Infrastructure Sortie) │
   ├─────────────────────────┤      ├──────────────────────────┤
   │                         │      │                          │
   │  DCS Enforcer           │      │  Repository              │
   │  ├── PIP Provider       │      │  ├── PostgreSQL          │
   │  │   (attributs)        │      │  │   - FilmRepo          │
   │  ├── PDP Engine         │      │  │   - UserRepo          │
   │  │   (décision)         │      │  │   - AuditRepo         │
   │  ├── PEP Appliers       │      │  └── Memory              │
   │  │   (enforcement)      │      │      - FilmRepo (mock)   │
   │  └── KMS                │      │                          │
   │      ├── Vault Transit  │      └──────────────────────────┘
   │      └── Local (mock)   │
   │                         │
   │  Cache Manager          │
   │  ├── Classification     │
   │  ├── PDP Decisions      │
   │  ├── KMS Results        │
   │  └── HMAC Pepper        │
   │                         │
   │  Audit Service          │
   │  Performance Service    │
   │                         │
   └─────────────────────────┘
```

### 4.5 Workflow Complet : Traitement d'une Requête DCS

Prenons l'exemple d'une **création de film** (`POST /films`) par un utilisateur **agent** :

```
┌────────────────────────────────────────────────────────────────────────────┐
│  WORKFLOW COMPLET : POST /films (Create Film) - Role: agent                │
└────────────────────────────────────────────────────────────────────────────┘

1️⃣  CLIENT (Browser)
    │
    │ POST /api/go/films
    │ Headers: { Authorization: "Bearer eyJhbG..." }
    │ Body: { "title": "Interstellar", "time_elapsed": 120 }
    │
    ▼
┌───────────────────────────────────────────────────────────────────────────┐
│ 2️⃣  TRANSPORT LAYER (HTTP Handler)                                        │
├───────────────────────────────────────────────────────────────────────────┤
│   - Parse JWT → Extract Principal {                                       │
│       tenant_id: "t1"                                                     │
│       user_id: "agent-1"                                                  │
│       role: "agent"                                                       │
│     }                                                                     │
│   - Build RequestContext {                                                │
│       request_id: "req-12345"                                             │
│       client_ip: "192.168.1.10"                                           │
│       channel: "web"                                                      │
│     }                                                                     │
│   - Call: filmService.Create(ctx, principal, reqCtx, input)               │
└───────────────────────────────────────────────────────────────────────────┘
    │
    ▼
┌───────────────────────────────────────────────────────────────────────────┐
│ 3️⃣  SERVICE LAYER (FilmService.Create)                                    │
├───────────────────────────────────────────────────────────────────────────┤
│                                                                           │
│   Phase 1: AUTHORIZATION (Write action)                                  │
│   ┌─────────────────────────────────────────────────────────────┐        │
│   │ enforcer.EvaluateFilmCreate(ctx, principal, reqCtx)         │        │
│   │   ↓                                                         │        │
│   │   PIP: Build PolicyInput {                                  │        │
│   │     principal: { role: "agent", tenant: "t1", user: "..." } │        │
│   │     action: "film.create"                                   │        │
│   │     resource: { type: "film", tenant: "t1" }                │        │
│   │     context: { request_id: "req-12345", ... }               │        │
│   │   }                                                         │        │
│   │   ↓                                                         │        │
│   │   PDP: Evaluate(policyInput) → Decision {                   │        │
│   │     allow: true                                             │        │
│   │     reason: "agent_can_write"                               │        │
│   │     hash: "sha256:abc123..."                                │        │
│   │   }                                                         │        │
│   └─────────────────────────────────────────────────────────────┘        │
│                                                                           │
│   ✅ Decision.Allow = true → Continue                                     │
│                                                                           │
│   Phase 2: ENCRYPT SENSITIVE DATA                                        │
│   ┌─────────────────────────────────────────────────────────────┐        │
│   │ kms.Encrypt(ctx, "120")                                     │        │
│   │   → Vault Transit API call                                 │        │
│   │   → ciphertext: "vault:v1:8SDd3WHD..."                      │        │
│   └─────────────────────────────────────────────────────────────┘        │
│                                                                           │
│   Phase 3: PERSIST TO DATABASE                                           │
│   ┌─────────────────────────────────────────────────────────────┐        │
│   │ repo.Create(ctx, tenantID, title, ciphertext)               │        │
│   │   → INSERT INTO films (tenant_id, title, time_elapsed_ct)   │        │
│   │      VALUES ('t1', 'Interstellar', 'vault:v1:8SDd3...')     │        │
│   │   → RETURNING id, title, time_elapsed_ct, created_at        │        │
│   │                                                             │        │
│   │ created = FilmRecord {                                       │        │
│   │   ID: "film-789"                                            │        │
│   │   Title: "Interstellar"                                     │        │
│   │   TimeElapsedCT: "vault:v1:8SDd3..."                        │        │
│   │ }                                                           │        │
│   └─────────────────────────────────────────────────────────────┘        │
│                                                                           │
│   Phase 4: APPLY READ POLICY (Read-Shaped Response)                      │
│   ┌─────────────────────────────────────────────────────────────┐        │
│   │ enforcer.EnforceFilmRead(ctx, principal, reqCtx, {          │        │
│   │   FilmID: "film-789",                                       │        │
│   │   Title: "Interstellar",                                    │        │
│   │   TimeElapsedCT: "vault:v1:8SDd3..."                        │        │
│   │ })                                                          │        │
│   │   ↓                                                         │        │
│   │   PIP: Build PolicyInput (action="film.read")               │        │
│   │   PDP: Evaluate → Decision {                                │        │
│   │     allow: true,                                            │        │
│   │     field_actions: {                                        │        │
│   │       "title": "allow",                                     │        │
│   │       "time_elapsed": "decrypt"  ← Agent voit SENSITIVE     │        │
│   │     }                                                       │        │
│   │   }                                                         │        │
│   │   ↓                                                         │        │
│   │   PEP: Apply(decision, filmRow) {                           │        │
│   │     - title: "Interstellar" (allow → passthrough)           │        │
│   │     - time_elapsed: decrypt via KMS                         │        │
│   │       kms.Decrypt("vault:v1:8SDd3...") → "120"              │        │
│   │       → Convert to int: 120                                 │        │
│   │   }                                                         │        │
│   │   ↓                                                         │        │
│   │ result = FilmReadResult {                                   │        │
│   │   TimeElapsed: 120,                                         │        │
│   │   FieldsDecrypted: ["time_elapsed"]                         │        │
│   │   FieldsMasked: []                                          │        │
│   │   FieldsDenied: []                                          │        │
│   │ }                                                           │        │
│   └─────────────────────────────────────────────────────────────┘        │
│                                                                           │
│   Phase 5: AUDIT LOGGING                                                 │
│   ┌─────────────────────────────────────────────────────────────┐        │
│   │ audit.WriteAudit(ctx, {                                     │        │
│   │   request_id: "req-12345",                                  │        │
│   │   tenant_id: "t1",                                          │        │
│   │   subject_user_id: "agent-1",                               │        │
│   │   subject_role: "agent",                                    │        │
│   │   action: "film.create",                                    │        │
│   │   resource_type: "film",                                    │        │
│   │   resource_id: "film-789",                                  │        │
│   │   outcome: "allow",                                         │        │
│   │   decision_hash: "sha256:abc123...",                        │        │
│   │   details: { title: "Interstellar", ... },                  │        │
│   │   fields_decrypted: ["time_elapsed"],                       │        │
│   │   fields_masked: [],                                        │        │
│   │   fields_denied: []                                         │        │
│   │ })                                                          │        │
│   │   → INSERT INTO audit_log (...)                             │        │
│   └─────────────────────────────────────────────────────────────┘        │
│                                                                           │
│   Phase 6: PERFORMANCE LOGGING                                           │
│   ┌─────────────────────────────────────────────────────────────┐        │
│   │ perf.Write(ctx, {                                           │        │
│   │   request_id: "req-12345",                                  │        │
│   │   action: "film.create",                                    │        │
│   │   total_ms: 45.2,                                           │        │
│   │   pip_ms: 2.1,                                              │        │
│   │   pdp_ms: 1.8,                                              │        │
│   │   kms_ms: 18.5,                                             │        │
│   │   db_ms: 12.3,                                              │        │
│   │   dcs_enabled: true,                                        │        │
│   │   cache_level: 2                                            │        │
│   │ })                                                          │        │
│   │   → INSERT INTO perf_log (...)                              │        │
│   └─────────────────────────────────────────────────────────────┘        │
│                                                                           │
│   Return: FilmOutput {                                                   │
│     ID: "film-789",                                                      │
│     Title: "Interstellar",                                               │
│     TimeElapsed: 120  ← Déchiffré pour l'agent                          │
│   }                                                                      │
└───────────────────────────────────────────────────────────────────────────┘
    │
    ▼
┌───────────────────────────────────────────────────────────────────────────┐
│ 4️⃣  RESPONSE (HTTP 201 Created)                                           │
├───────────────────────────────────────────────────────────────────────────┤
│   {                                                                       │
│     "id": "film-789",                                                     │
│     "title": "Interstellar",                                              │
│     "time_elapsed": 120                                                   │
│   }                                                                       │
└───────────────────────────────────────────────────────────────────────────┘
```

**Si c'était un `developer` à la place :**

Phase 4 changerait :
```
PDP Decision {
  field_actions: {
    "title": "allow",
    "time_elapsed": "mask_after_decrypt"  ← Developer voit SENSITIVE masqué
  }
}

PEP Apply:
  - time_elapsed: decrypt("vault:v1:...") → "120"
                  → mask("120") → "1***"

Response: {
  "time_elapsed": "1***"  ← Masqué !
}
```

### 4.6 Flux de Données (Diagramme Séquence)

```
Client    HTTP      Service      Enforcer    PIP    PDP    PEP    KMS    Repo   Audit
  │       │          │            │         │      │      │      │      │      │
  │─POST─>│          │            │         │      │      │      │      │      │
  │       │──Create->│            │         │      │      │      │      │      │
  │       │          │──Evaluate─>│         │      │      │      │      │      │
  │       │          │            │──Build->│      │      │      │      │      │
  │       │          │            │<────────│      │      │      │      │      │
  │       │          │            │─────Eval────>│ │      │      │      │      │
  │       │          │            │<──Decision───│ │      │      │      │      │
  │       │          │<───────────│         │      │      │      │      │      │
  │       │          │──Encrypt──────────────────────────>│      │      │      │
  │       │          │<────CT─────────────────────────────│      │      │      │
  │       │          │──────────────────────────────────Insert──>│      │      │
  │       │          │<───────────────────────────────────Record─│      │      │
  │       │          │──Enforce──>│         │      │      │      │      │      │
  │       │          │            │──Build->│      │      │      │      │      │
  │       │          │            │─────Eval────>│ │      │      │      │      │
  │       │          │            │─────────Apply───────> │      │      │      │
  │       │          │            │<─────────Result────── │      │      │      │
  │       │          │<───────────│         │      │      │      │      │      │
  │       │          │─────────────────────────────────────────────────>│      │
  │       │          │────────────────────────────────────────────────────────>│
  │       │<─Response│            │         │      │      │      │      │      │
  │<─JSON─│          │            │         │      │      │      │      │      │
```

### 4.7 Points Clés du Design DCS

1. **Enforcement au plus près de la donnée** : Le PEP est dans le backend, pas juste au réseau
2. **Métadonnées persistées** : Classification, owner_id, labels en DB
3. **Décisions granulaires** : Par champ, pas par ressource
4. **Chiffrement systématique** : Les champs sensibles n'existent QUE chiffrés en DB
5. **Audit complet** : Chaque décision loguée avec détails (fields_decrypted/masked/denied)
6. **Architecture découplée** : PIP/PDP/PEP via interfaces → évolutivité
7. **Graceful degradation** : Le système continue même si audit/perf down
8. **Cache intelligent** : PDP cache par (role × classification × action)


## 5) Décisions DCS prises (et pourquoi)

### 5.1 Où se fait l’enforcement ?
- **Le vrai contrôle est côté backend**, au plus près de la donnée : c’est lui qui sait :
  - ce que contient la ressource (et ses métadonnées),
  - quels champs sont sensibles,
  - quoi déchiffrer/masquer/supprimer avant réponse.

Ça évite l’illusion “on a mis un WAF / un proxy donc c’est bon”. Ici le **PEP données** est le point dur.

### 5.2 Métadonnées “accrochées” aux données
Le DCS a besoin de métadonnées **persistées** et **fiables**, typiquement :
- `tenant_id` : séparation multi-tenant (frontière d’isolement forte)
- `owner_user_id` : propriété / responsabilité (utile pour policies du type “owner can see more”)
- `labels` : tags métier (ex: “minor”, “vip”, “internal-use”, “screening”)
- `field_classification` : classification des champs par type de ressource (Film/Hall/Spectator)
- audit : “qui a vu quoi”, “quels champs ont été déchiffrés/masqués/refusés”

### 5.3 Modèle de policy
On utilise une logique **ABAC simple** :
- subject : role, tenant, user_id
- resource : type, id, tenant, owner_id, labels, classification des champs
- context : endpoint/action, timestamp, etc.

Le PDP renvoie une décision :
- `allow` / `deny`
- et pour chaque champ : `allow` / `decrypt` / `mask_after_decrypt` / `deny`

C’est **beaucoup plus démonstratif** qu’un RBAC “tout ou rien” et colle mieux au DCS.

### 5.4 Chiffrement : choix actuel vs cible

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

### 5.5 Recherche SQL sur donnée chiffrée (cas utile)
Pour `Spectator.external_id` (ticket) :
- on chiffre le ticket (`external_id_ct`) pour la confidentialité,
- et on stocke un **HMAC** (`external_id_lookup`) pour permettre une recherche exacte (`WHERE external_id_lookup = ...`) sans stocker le ticket en clair.

La clé de HMAC (“pepper”) est stockée dans **Vault KV** et jamais en DB.

### 5.6 Niveaux de caches
- **Classification cache (L1)**  
  - Clé: `resource_type`  
  - Valeur: `dict[field_name -> classification]`  

- **Pepper cache (L1)**  
  - Clé fixe: `"pepper"`  
  - Valeur: `bytes`  

- **PDP decision cache (L2)**  
  - Activé pour `film.read` et `film.update_time` uniquement  
  - Clé riche: `dcs_enabled`, action, tenant, role, user, owner, labels, signature des classifications (`_decision_cache_key`)  

- **KMS decrypt cache (L3)**  
  - Clé: ciphertext complet  
  - Valeur: plaintext déchiffré  


## 6) Schéma de données (vue logique)

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




## 7) État du projet (à date)

✅ **Backend Python (FastAPI)** — Fonctionnel :
- dockerisation + run via compose
- authentification JWT (login dev/agent/admin)
- endpoints métier : films, halls, spectators, audit
- chiffrement/déchiffrement via Vault Transit
- classification par champ via table `field_classification`
- décision PDP par action + classification + rôle
- enforcement PEP : decrypt / mask / deny par champ
- recherche spectator par ticket via HMAC lookup
- UI connectée au backend Python

✅ **Backend Go** — Fonctionnel :
- architecture hexagonale complète (Ports & Adapters)
- implémentation DCS modulaire :
  - PIP : Policy Information Point
  - PDP : Policy Decision Point avec cache LRU
  - PEP : Policy Enforcement Point par ressource
  - Enforcer : orchestration DCS
- services métier : films, halls, spectators, audit, perf
- double implémentation repository : PostgreSQL + Memory (dev/test)
- double implémentation KMS : Vault Transit + Local (mock)
- JWT authentication
- audit complet (decision hash, fields tracking)
- performance tracking (context propagation)
- tests unitaires complets (>80% coverage)
- graceful degradation (fallbacks automatiques)
- HTTP ready + gRPC prepared (proto definitions)

✅ **Infrastructure** :
- Frontend React + TypeScript + Vite
- Nginx gateway (reverse proxy)
- PostgreSQL (données + métadonnées + audit)
- Vault Transit (KMS) + KV (pepper HMAC)
- Docker Compose orchestration

⚠️ **Limites assumées du PoC** :
- PIP/PDP dans le backend (pas encore des services séparés)
- chiffrement direct via KMS (pas encore envelope encryption)
- authN/authZ simplifiés (seed users, pas d'IdP, pas de rotation JWT)
- réseau "minimal" (pas mTLS, pas d'attestation device)
- policies "policy-as-code" dans le repo (pas de PAP dédié ni workflow de déploiement des politiques)

### 7.1 Comparaison Backend Python vs Go

Le projet implémente **deux backends en parallèle** pour démontrer deux approches architecturales :

| Aspect | Backend Python | Backend Go |
|--------|---------------|------------|
| **Architecture** | Transaction Script | Hexagonal (Ports & Adapters) |
| **Logique métier** | Dans les routers HTTP | Dans service layer (use cases) |
| **DCS Integration** | Fonctions globales | Couche Enforcer + interfaces |
| **Testabilité** | Limitée (couplage fort) | Excellente (interfaces mockables) |
| **Séparation** | 2-3 couches | 5-6 couches bien définies |
| **Dépendances** | Imports directs, globals | Injection via constructeurs |
| **Adapters** | Non interchangeables | Interchangeables (Postgres↔Memory) |
| **Évolutivité** | Refactoring nécessaire | Architecture extensible |
| **Performance** | Acceptable (async) | Meilleure (compiled, concurrence) |
| **Cas d'usage** | PoC rapide, prototypage | Production, scalabilité |


---

## Références (base conceptuelle)
- NIST SP 800‑207 (Zero Trust Architecture)
- NIST SP 800‑162 (ABAC : PDP/PEP/PIP et modèle attributs)
- HashiCorp Vault Transit (docs + API)
