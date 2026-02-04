.PHONY: install dev lint lint-fix test coverage clean

# Install all dependencies
install:
	cd backend && uv sync --extra dev
	cd frontend && npm install

# Start development servers
dev:
	docker-compose up -d

# Run all linters
lint:
	cd backend && uv run ruff check app/
	cd frontend && npm run lint

# Fix linting issues
lint-fix:
	cd backend && uv run ruff check app/ --fix
	cd frontend && npm run lint:fix

# Run all tests
test:
	cd backend && uv run pytest
	cd backend-go && go test ./...
	cd frontend && npm test

# Run tests with coverage
coverage:
	cd backend && uv run pytest --cov=app --cov-report=html
	cd frontend && npm run coverage

# Clean build artifacts
clean:
	rm -rf backend/.pytest_cache
	rm -rf backend/.ruff_cache
	rm -rf backend/htmlcov
	rm -rf backend/.coverage
	rm -rf frontend/dist
	rm -rf frontend/coverage
	rm -rf frontend/node_modules/.vite
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
