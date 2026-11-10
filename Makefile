.PHONY: up dev seed test lint format compliance package-windows package-macos package-deb package-all

up:
	docker compose up --build

dev:
	npm run dev

seed:
	npm run migrate
	npm run seed

test:
	npm test

lint:
        npm run lint

format:
        npm run format

compliance:
        npm run compliance

package-windows:
        npm run package:windows

package-macos:
        npm run package:macos

package-deb:
        npm run package:deb

package-all:
        npm run package:all
