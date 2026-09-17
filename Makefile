COMPOSE := docker compose --env-file .env

.DEFAULT_GOAL := help

help: ## Liet ke lenh
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

.env: ## Tao .env tu mau
	@test -f .env || cp .env.example .env

up: .env ## Build + chay toan bo stack
	$(COMPOSE) up -d --build
	$(COMPOSE) ps

down: ## Dung stack (giu du lieu)
	$(COMPOSE) down

destroy: ## Dung stack + xoa volume (MAT DU LIEU)
	$(COMPOSE) down -v

restart: ## Restart stack
	$(COMPOSE) restart

logs: ## Xem log tat ca service
	$(COMPOSE) logs -f --tail=100

logs-proxy: ## Log data plane
	$(COMPOSE) logs -f --tail=200 proxy

logs-mgmt: ## Log control plane
	$(COMPOSE) logs -f --tail=200 mgmt

ps: ## Trang thai container
	$(COMPOSE) ps

shell-proxy: ## Vao shell container OpenResty
	$(COMPOSE) exec proxy sh

nginx-test: ## Kiem tra cu phap nginx dang chay
	$(COMPOSE) exec proxy openresty -t

reload: ## Reload data plane
	$(COMPOSE) exec proxy openresty -s reload

# ---------- phat trien local (khong can docker) ----------

web-dev: ## Chay Vue dev server (proxy API ve https://localhost:9443)
	cd web && npm install && npm run dev

web-build: ## Build dashboard vao control/internal/web/dist
	cd web && npm install && npm run build

go-build: ## Build binary control plane
	cd control && go build -o bin/moswafd ./cmd/moswafd

go-test: ## Test control plane
	cd control && go vet ./... && go test ./...

fmt: ## Format Go
	cd control && gofmt -w .

lua-check: ## Kiem tra cu phap engine Lua (can luajit: brew install luajit)
	@command -v luajit >/dev/null || { echo "Thieu luajit: brew install luajit"; exit 1; }
	@for f in $$(find dataplane/lua -name '*.lua'); do \
		luajit -b $$f /dev/null || exit 1; \
	done
	@echo "Cu phap Lua OK"

.PHONY: help up down destroy restart logs logs-proxy logs-mgmt ps shell-proxy nginx-test reload web-dev web-build go-build go-test fmt lua-check
