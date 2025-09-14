.PHONY: build run test clean docker frontend dev

build: frontend
	go build -trimpath -ldflags="-s -w" -o mkbox . 
	

frontend:
	pnpm install
	pnpm run build

run: build
	./mkbox -daemon

test:
	go test ./...

clean:
	rm -f mkbox
	rm -f public/background.js
	rm -f public/background.js.map

docker:
	docker-compose up -d

docker-build:
	docker-compose build

docker-stop:
	docker-compose down

dev:
	pnpm install
	pnpm run dev
