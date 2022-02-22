PROJECT_NAME="github.com/nobuenhombre/go-crypto-gost"

help: Makefile
	@echo "Выберите опицию сборки "$(BINARY_NAME)":"
	@sed -n 's/^##//p' $< | column -s ':' |  sed -e 's/^/ /'

## all: Удалить старые сборки, скачать необходимые пакеты, протестировать, скомпилировать
all: clean deps test build

## test: Запустить тесты
test:
	go test -v ./...

## cover: Получить информацию о покрытии тестами кода
cover:
	go test -coverprofile=cover.out ./...
	go tool cover -html=cover.out -o cover.html
	rm -f cover.out

## codecove: Бейджик Покрытия на гитхабе
codecove:
	for d in $(shell go list ./...); do \
		go test -v -covermode=count -coverprofile=profile.out $$d > tmp.out; \
		cat tmp.out; \
		if grep -q "^--- FAIL" tmp.out; then \
			rm tmp.out; \
			exit 1; \
		elif grep -q "build failed" tmp.out; then \
			rm tmp.out; \
			exit 1; \
		elif grep -q "setup failed" tmp.out; then \
			rm tmp.out; \
			exit 1; \
		fi; \
		if [ -f profile.out ]; then \
			cat profile.out | grep -v "mode:" >> codecove.out; \
			rm profile.out; \
		fi; \
		rm -f tmp.out; \
	done; \
	echo "mode: count" > coverage.out; \
	cat codecove.out >> coverage.out; \
	gocov convert coverage.out | gocov-xml > coverage.xml;
	rm -f codecove.out;
	rm -f coverage.out;

## clean: Удалить старые сборки
clean:
	go clean
	rm -f cover.out

## deps: Инициализация модулей, скачать все необходимые програме модули
deps:
	rm -f go.mod
	rm -f go.sum
	go mod init $(PROJECT_NAME)
	go get -u ./...
	go mod tidy

## fmt: Автоформатирование
fmt:
	go fmt ./... && \
	./go-imports.sh;

## lint: Проверка кода линтерами
lint: fmt lint-standart lint-bugs lint-complexity lint-format lint-performance lint-style lint-unused

## lint-standart: Проверка кода стандартным набором линтереров
lint-standart:
	golangci-lint run ./...

## lint-bugs: Проверка кода линтерами bugs
lint-bugs:
	golangci-lint run -p=bugs ./...

## lint-complexity: Проверка кода линтерами complexity
lint-complexity:
	golangci-lint run -p=complexity ./...

## lint-format: Проверка кода линтерами format
lint-format:
	golangci-lint run -p=format ./...

## lint-performance: Проверка кода линтерами performance
lint-performance:
	golangci-lint run -p=performance ./...

## lint-style: Проверка кода линтерами style
lint-style:
	golangci-lint run -p=style ./...

## lint-unused: Проверка кода линтерами unused
lint-unused:
	golangci-lint run -p=unused ./...
