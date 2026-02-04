# Cinema DCS PoC – Frontend

Frontend React/TypeScript pour le système Cinema DCS avec Data-Centric Security.

## Stack Technique

- **React 18** - Framework UI
- **TypeScript** - Type safety
- **Vite 6** - Build tool et dev server
- **React Router 6** - Routing
- **ESLint 9** - Linting avec flat config
- **Vitest** - Tests unitaires
- **Testing Library** - Tests de composants React

## Prérequis

- Node.js ≥ 18.18.0
- npm ≥ 8

## Installation

```bash
npm install
```

## Commandes de Développement

```bash
# Serveur de développement (port 5173)
npm run dev

# Build de production
npm run build

# Prévisualisation du build
npm run preview

# Linting
npm run lint          # Vérifier le code
npm run lint:fix      # Corriger automatiquement

# Tests
npm test             # Exécuter les tests
npm run test:watch   # Mode watch
npm run coverage     # Rapport de couverture
```

## Structure du Projet

```
frontend/
├── src/
│   ├── api/           # API client et fonctions d'appel
│   ├── components/    # Composants réutilisables
│   ├── pages/         # Pages/routes
│   ├── state/         # Context API (auth)
│   ├── types/         # Types TypeScript
│   ├── test/          # Configuration de test
│   ├── App.tsx        # Composant principal
│   └── main.tsx       # Point d'entrée
├── public/            # Assets statiques
└── dist/              # Build de production (généré)
```

## Path Aliases

Le projet utilise des path aliases pour des imports plus propres:

```typescript
// Au lieu de
import { FilmCard } from '../../../components/FilmCard';

// Vous pouvez écrire
import { FilmCard } from '@/components/FilmCard';
```

Alias configurés:
- `@/` → `./src/`

## Configuration

### Variables d'Environnement

Créer un fichier `.env` (optionnel):

```bash
# URL de base de l'API (par défaut: /api)
VITE_API_BASE_URL=/api
```

### API Backend

L'application attend l'API backend à `/api` (via nginx gateway).

En développement local, Vite ne proxy pas automatiquement - utilisez `docker-compose` pour avoir nginx:

```bash
# Depuis la racine du repo
docker-compose up -d
```

L'application est alors disponible sur http://localhost:8080

## Authentification

L'application utilise JWT stocké dans `localStorage`:

- Login: POST `/api/auth/login`
- Token refresh automatique sur 401
- Context `AuthContext` pour l'état global

Utilisateurs de test (mot de passe: `password`):
- `developer` - Accès limité, champs sensibles masqués
- `agent` - Accès SENSITIVE, PII masqué après décryption
- `admin` - Accès complet incluant audit logs

## Tests

Les tests utilisent Vitest et React Testing Library:

```typescript
// Exemple: src/api/client.test.ts
import { describe, it, expect } from 'vitest';
import { ApiError } from './client';

describe('ApiError', () => {
  it('should create error with status', () => {
    const error = new ApiError(404, { msg: 'Not found' });
    expect(error.status).toBe(404);
  });
});
```

Exécuter les tests:

```bash
npm test                    # Run once
npm run test:watch          # Watch mode
npm run coverage            # Coverage report
```

## Linting

Le projet utilise ESLint 9 avec flat config:

```bash
npm run lint        # Vérifier
npm run lint:fix    # Auto-fix
```

Configuration: `eslint.config.js`

Règles principales:
- TypeScript strict
- React hooks rules
- Unused vars avec `_` prefix autorisé
- `any` en warning (pas erreur)

## Build et Déploiement

### Build de Production

```bash
npm run build
```

Génère `dist/` avec:
- Assets optimisés et minifiés
- Code splitting automatique
- Tree shaking

### Prévisualisation Locale

```bash
npm run preview
```

Serveur HTTP simple sur le build de production (port 5173).

### Docker

Le Dockerfile multi-stage est à la racine du repo:

```bash
# Depuis la racine
docker-compose up --build
```

Image finale: nginx servant les assets statiques.

## Conventions de Code

Voir [CLAUDE.md](../CLAUDE.md) à la racine pour les conventions complètes.

### Imports

Ordre recommandé:

```typescript
// React
import { useState, useEffect } from 'react';

// Third-party
import { useNavigate } from 'react-router-dom';

// Local avec path alias
import { useAuth } from '@/state/auth';
import { getFilms } from '@/api/films';
import type { Film } from '@/types';
```

### Composants

```typescript
// Props typées
interface FilmCardProps {
  film: Film;
  onSelect: (id: string) => void;
}

// Functional component
export function FilmCard({ film, onSelect }: FilmCardProps) {
  // ...
}
```

### Style

- 2 espaces d'indentation
- Single quotes
- Pas de point-virgule (laissé à Prettier)
- Pas d'emojis sauf si demandé explicitement

## Dépannage

### Port 5173 déjà utilisé

```bash
# Tuer le processus
lsof -ti:5173 | xargs kill -9

# Ou changer le port dans package.json
vite --port 3000
```

### Erreurs CORS en dev

Utiliser docker-compose avec nginx ou configurer le proxy Vite:

```typescript
// vite.config.ts
export default defineConfig({
  server: {
    proxy: {
      '/api': 'http://localhost:8000'
    }
  }
});
```

### Tests échouent

Vérifier que jsdom est installé:

```bash
npm install -D jsdom
```

### Build TypeScript échoue

```bash
# Nettoyer et rebuild
rm -rf node_modules/.vite dist
npm install
npm run build
```

## Ressources

- [React Documentation](https://react.dev/)
- [Vite Documentation](https://vitejs.dev/)
- [React Router](https://reactrouter.com/)
- [Vitest](https://vitest.dev/)
- [Testing Library](https://testing-library.com/react)
