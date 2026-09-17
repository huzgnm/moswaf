COMPOSE := docker compose --env-file .env

.DEFAULT_GOAL := help

help: ## List the available commands
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

.env: ## Create .env from the example, with real generated secrets
	@test -f .env && exit 0; \
	cp .env.example .env; \
	for key in MOSWAF_ADMIN_PASSWORD POSTGRES_PASSWORD REDIS_PASSWORD MOSWAF_JWT_SECRET MOSWAF_CHALLENGE_SECRET; do \
		secret=$$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 40); \
		sed -i.bak "s|^$$key=.*|$$key=$$secret|" .env; \
	done; \
	rm -f .env.bak; chmod 600 .env; \
	echo "Generated .env with fresh secrets. Admin password:"; \
	grep '^MOSWAF_ADMIN_PASSWORD=' .env

up: .env ## Build and start the whole stack
	$(COMPOSE) up -d --build
	$(COMPOSE) ps

down: ## Stop the stack, keeping all data
	$(COMPOSE) down

destroy: ## Stop the stack and delete its volumes (DESTROYS DATA)
	$(COMPOSE) down -v

restart: ## Restart the stack
	$(COMPOSE) restart

logs: ## Follow the logs of every service
	$(COMPOSE) logs -f --tail=100

logs-proxy: ## Follow the data plane logs
	$(COMPOSE) logs -f --tail=200 proxy

logs-mgmt: ## Follow the control plane logs
	$(COMPOSE) logs -f --tail=200 mgmt

ps: ## Show container status
	$(COMPOSE) ps

shell-proxy: ## Open a shell in the OpenResty container
	$(COMPOSE) exec proxy sh

nginx-test: ## Validate the running nginx configuration
	$(COMPOSE) exec proxy openresty -t

reload: ## Reload the data plane
	$(COMPOSE) exec proxy openresty -s reload

# ---------- local development (no docker needed) ----------

web-dev: ## Run the Vue dev server (API proxied to https://localhost:9443)
	cd web && npm install && npm run dev

web-build: ## Build the dashboard into control/internal/web/dist
	cd web && npm install && npm run build

go-build: ## Build the control plane binary
	cd control && go build -o bin/moswafd ./cmd/moswafd

go-test: ## Vet and test the control plane
	cd control && go vet ./... && go test ./...

fmt: ## Format the Go code
	cd control && gofmt -w .

lua-check: ## Check the Lua engine syntax (needs luajit: brew install luajit)
	@command -v luajit >/dev/null || { echo "luajit is missing: brew install luajit"; exit 1; }
	@for f in $$(find dataplane/lua -name '*.lua'); do \
		luajit -b $$f /dev/null || exit 1; \
	done
	@echo "Lua syntax OK"

.PHONY: help up down destroy restart logs logs-proxy logs-mgmt ps shell-proxy nginx-test reload web-dev web-build go-build go-test fmt lua-check
