.PHONY: clean cov lint test vet

## clean: cleans the binary
clean:
	@echo "Cleaning..."
	@go clean

## cov: generates coverage report
cov:
	@echo "Coverage..."
	@go test -cover ./...

## lint: lint codebase
lint:
	@echo "Linting code..."
	@golangci-lint run --fix

## test: runs unit tests
test:
	@echo "Running unit tests..."
	@go test -v ./...

## vet: code analysis
vet:
	@echo "Running code analysis..."
	@go vet ./...