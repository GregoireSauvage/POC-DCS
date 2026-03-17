# Cinema DCS PoC

PoC de Data-Centric Security (DCS) applique a un systeme de cinema. Le projet demontre un controle d'acces au niveau du champ, un chiffrement applicatif via Vault Transit, un binding d'integrite anti-tampering, et un modele Zero Trust pilote par des metadonnees.

Le depot contient :
- un frontend React/Vite,
- une gateway Nginx,
- un backend Go qui porte l'architecture canonique actuelle,
- un backend Python/FastAPI conserve dans le depot pour comparaison et experimentation,
- PostgreSQL pour les donnees, metadonnees, audit et perf,
- Vault comme KMS.

## Objectif

Le projet montre concretement comment proteger la donnee elle-meme, et pas seulement l'entree HTTP ou le reseau :
- decisions d'acces par champ : `allow`, `decrypt`, `mask`, `deny`,
- chiffrement a l'ecriture et dechiffrement controle a la lecture,
- separation explicite des responsabilites PIP / PDP / PEP,
- audit des decisions et observabilite des performances,
- detection d'alteration via binding.

## Cas metier

Le domaine simule est un systeme de suivi de projection :
- `Film` : `id`, `title`, `time_elapsed`
- `Hall` : `id`, `name`, `owner_user_id`, `current_film_id`, `spectator_count`
- `Spectator` : `id`, `hall_id`, `name`, `age`, `external_id`

Roles exposes dans le PoC :
- `developer` : acces lecture, donnees sensibles/PII masquees
- `agent` : voit le `SENSITIVE` dechiffre, PII masquee
- `admin` : acces complet, y compris audit et configuration

Classifications utilisees :
- `PUBLIC`
- `INTERNAL`
- `SENSITIVE`
- `PII`

## Ce que le DCS signifie dans ce projet

Le DCS est ici une combinaison de quatre mecanismes.

### 1. Classification

Chaque champ utile a la securite porte une classification. La decision ne se prend pas uniquement sur la ressource, mais champ par champ.

### 2. Decision ABAC

La decision combine :
- les attributs du sujet : role, tenant, identifiants,
- les attributs de ressource : owner, labels, classification, tenant,
- le contexte : action, transport, environnement.

### 3. Enforcement data-level

Les obligations ne sont pas laissees au handler HTTP. Elles sont appliquees au plus pres de la donnee : dechiffrement controle, masquage, refus, reecriture securisee.

### 4. Binding d'integrite

Chaque donnee protegee est liee cryptographiquement a un snapshot de label/policy. Une alteration directe en base provoque un refus de lecture.

## PIP / PDP / PEP dans l'architecture actuelle

Le projet ne possede plus de module DCS separe. Le DCS est reparti dans les couches du backend.

- PIP : responsabilite repartie
  - `transport` fournit le sujet, l'action et le contexte
  - `repository` charge les metadonnees de ressource, classifications et labels
- PDP : porte par `service/authorization`
  - decision a partir d'un `AccessContext` et d'une `Resource`
- PEP : principalement porte par `repository/postgres/secured`
  - binding verify
  - chiffrement/dechiffrement
  - HMAC lookup
  - masquage
  -  refus
  - write atomique `row + binding`

## Architecture globale

```text
Browser
  -> Nginx
    -> Backend Go
    -> Backend Python (comparaison / experimentation)
      -> PostgreSQL
      -> Vault Transit
```

Role des composants :
- Frontend : interface utilisateur, login, navigation, demonstration des effets du DCS
- Nginx : point d'entree HTTP
- Backend Go : implementation canonique actuelle de l'architecture DCS
- Backend Python : implementation alternative conservee dans le repo
- PostgreSQL : donnees metier, classifications, audit, perf, bindings
- Vault : chiffrement/dechiffrement Transit et pepper/HMAC selon le flux

### Schema 1 - Vue d'ensemble de l'architecture

```text
                               +------------------+
                               |     Frontend     |
                               |    React/Vite    |
                               +---------+--------+
                                         |
                                         v
                               +------------------+
                               |      Nginx       |
                               |  entry gateway   |
                               +----+--------+----+
                                    |        |
                    /api/go/*       |        |      /api/py/*
                                    v        v
                        +----------------+  +----------------+
                        |   Backend Go   |  | Backend Python |
                        |                |  |                |
                        |                |  |                |
                        +--------+-------+  +--------+-------+
                                 |                   |
                                 +---------+---------+
                                           |
                      +--------------------+--------------------+
                      |                                         |
                      v                                         v
            +----------------------+                 +----------------------+
            |      PostgreSQL      |                 |        Vault         |
            | business data        |                 | transit / pepper     |
            | classifications      |                 | crypto primitives    |
            | audit / perf         |                 +----------------------+
            | resource bindings    |
            +----------------------+
```

## Architecture canonique du backend Go

Le backend Go suit l'architecture suivante :

```text
backend-go/internal/
├── transport/
├── service/
├── domain/
├── repository/
├── infra/
├── auth/
├── config/
├── bootstrap/
└── observability/
```

### `transport`

Responsabilites :
- authentification et extraction du principal,
- mapping route/methode vers action,
- construction du `AccessContext`,
- propagation dans `context.Context`,
- exposition HTTP et gRPC.

Notes actuelles :
- le transport nominal est HTTP,
- le transport gRPC existe cote backend Go, mais le perimetre expose reste limite.

### `service`

Responsabilites :
- use cases,
- contrats applicatifs,
- types DCS canoniques,
- construction du `PolicyInput`,
- PDP via `service/authorization`.

On y trouve notamment :
- `AccessContext`
- `Decision`
- `FieldAction`
- `Label`
- `BindingRecord`
- `Authorizer`

La regle directrice est :
- `service` decide,
- `repository` applique.

### `domain`

Responsabilites :
- entites metier stables,
- structures de donnees du domaine,
- classifications portees cote modele quand necessaire.

### `repository`

Responsabilites :
- acces aux donnees,
- chargement des metadonnees de ressource,
- enforcement au plus pres de la donnee,
- application des obligations non negociables.

Le package cle cote PostgreSQL est :
- `internal/repository/postgres/secured`

C'est la que vivent les repositories avec enforcement :
- verification de binding,
- dechiffrement et masquage,
- writes transactionnels avec binding,
- shaping final des vues exposees.

### `infra`

Responsabilites :
- KMS (`infra/kms`)
- binding (`infra/binding`)
- cache technique (`infra/cache`)
- SPIF/policy provider (`infra/spif`)

Ces composants sont techniques. Ils ne prennent pas de decision metier.

### `bootstrap`

Responsabilites :
- composition root,
- wiring des dependances,
- assemblage runtime : config, infra, repos, services, transport.

C'est la couche qui connait tout le graphe d'objets. C'est normal qu'elle importe a la fois `infra`, `repository`, `service` et `transport`.

### Schema 2 - DCS distribue dans la clean architecture

```text
HTTP / gRPC request
        |
        v
+-----------------------+
| transport             |
| - auth                |
| - route -> action     |
| - AccessContext       |
+-----------+-----------+
            |
            v
+-----------------------+
| service               |
| - use case            |
| - build PolicyInput   |
| - PDP / Authorizer    |
| - Decision            |
+-----------+-----------+
            |
            v
+-----------------------+
| repository            |
| - load raw row        |
| - load metadata       |
| - verify binding      |
| - apply Decision      |
| - encrypt/decrypt     |
| - mask / deny         |
+-----------+-----------+
            |
            v
+-----------------------+
| PostgreSQL            |
| - rows                |
| - classifications     |
| - bindings            |
| - audit / perf        |
+-----------------------+

infra fournit les primitives consommees par le runtime :
- `infra/kms`
- `infra/binding`
- `infra/cache`
- `infra/spif`
```

## Flux d'une requete protegee

### Schema 3 - Cycle PDP / PEP sur une lecture

```text
1. transport
   principal + action + contexte
                |
                v
2. repository
   row brute + metadata + binding
                |
                v
3. service / PDP
   Authorizer(AccessContext, Resource) -> Decision
                |
                v
4. repository / PEP
   apply Decision:
   - decrypt
   - mask
   - deny
   - shape response
                |
                v
5. service
   audit + perf
                |
                v
6. response
```

### Lecture

1. le transport authentifie et construit le `AccessContext`
2. le service identifie l'action et prepare les donnees necessaires au PDP
3. le repository lit la donnee brute et verifie le binding
4. le service appelle le `Authorizer`
5. le repository applique la `Decision`
6. le service ecrit audit/perf
7. la reponse HTTP est renvoyee

Au niveau du repository, l'application de la decision signifie typiquement :
- `decrypt`
- `mask`
- `deny`

### Ecriture

1. le transport construit le `AccessContext`
2. le service appelle le `Authorizer` sur l'action d'ecriture
3. le repository chiffre les champs necessaires
4. le repository ecrit la row metier
5. le repository genere et persiste le binding dans la meme transaction
6. le service peut declencher une decision de lecture pour la reponse retournee
7. audit et perf sont ecrits

## Binding d'integrite

Le binding sert a empecher qu'une donnee protegee soit modifiee directement en base sans detection.

Le principe est :
- construction d'un payload canonique,
- construction d'un label snapshot,
- calcul de `payload_hash`,
- calcul de `label_hash`,
- generation d'une preuve HMAC,
- stockage dans une table dediee de bindings.

A la lecture :
- le repository recharge la donnee,
- recalcule les hashes,
- verifie la preuve,
- refuse immediatement si le binding est absent, invalide ou corrompu.

Le binding protege donc :
- l'integrite du payload,
- l'integrite du label de securite,
- le lien entre donnee et policy.

## Securite appliquee par ressource

### Film

- `title` : `PUBLIC`
- `time_elapsed` : `SENSITIVE`

Effets typiques :
- `developer` : valeur masquee
- `agent` : valeur dechiffree
- `admin` : valeur dechiffree

### Hall

- `name` : `PUBLIC`
- `owner_user_id` : `INTERNAL`
- `current_film_id` : `INTERNAL`

Effets typiques :
- `developer` : champs internes masques
- `admin` : visibilite complete

### Spectator

- `name` : `PII`
- `age` : `SENSITIVE`
- `external_id` : `PII`

Effets typiques :
- `developer` : PII masquee
- `agent` : `SENSITIVE` lisible, PII masquee
- `admin` : visibilite complete

Le champ `external_id` reste recherchable via lookup HMAC sans exposer la valeur en clair dans la base.

## Configuration runtime importante

Variables utiles :
- `DCS_MODE` : `on` ou `off`
- `CACHE_LEVEL` : niveau de cache technique
- `DCS_BINDING_HMAC_KEY` : cle HMAC obligatoire pour le binding
- `DCS_CONFIG_PATH` : chemin du fichier de config DCS versionnee
- `VAULT_ADDR`, `VAULT_TOKEN`, `VAULT_TRANSIT_KEY` : configuration KMS Vault
- `LOG_LEVEL`

Le backend Go charge aussi une policy versionnee qui alimente :
- `policy_id`
- `policy_version`
- labels et regles associees

## Lancer le projet

### Stack complete

```bash
docker compose up -d
```

Points d'acces usuels :
- application : `http://localhost:8080`
- backend Python direct : `http://localhost:8000`
- frontend Vite en dev : `http://localhost:5173`

### Identifiants de demonstration

Utilisateurs seedes :
- `dev` / `password`
- `agent` / `password`
- `admin` / `password`

## Developpement

### Frontend

```bash
cd frontend
npm run dev
npm run build
npm run lint
npm test
```

### Backend Python

```bash
cd backend
uv sync
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
pytest
```

### Backend Go

```bash
cd backend-go
go test ./...
```

## Observabilite

Le projet trace deux dimensions :
- audit : qui a accede a quoi, sous quelle decision
- perf : temps d'execution des endpoints et operations principales

Cote backend Go, l'observabilite fait partie du runtime nominal :
- audit admin,
- propagation de `policy_id` et `policy_version`,
- mesures de perf par endpoint.

## Pourquoi cette architecture est utile pour un PoC DCS

Cette structure permet de garder les concepts de securite visibles sans recreer un sous-systeme DCS parallele :
- le transport prepare le contexte,
- le service decide,
- le repository applique au plus pres de la donnee,
- l'infra fournit les briques techniques.

Le resultat est un backend ou le DCS n'est pas une extension laterale, mais une propriete normale de l'architecture.
