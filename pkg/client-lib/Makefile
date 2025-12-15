.PHONY: genrest

ark_client_dir = $(or $(REST_DIR),client/rest/service)
indexer_client_dir = $(or $(REST_DIR),indexer/rest/service)

SWAGGER = $(shell \
	echo "docker run --rm \
		-v $(shell realpath ../..):/work -w /work \
		openapitools/openapi-generator-cli:v7.16.0"; \
)

## genrest: compiles rest client from stub with https://github.com/go-swagger/go-swagger
genrest:
	@if [ "$(CI)" != "true" ]; then \
		$(MAKE) proto; \
	else \
		echo "Skipping proto (CI=true passed)"; \
	fi
	@echo "Cleaning existing files..."
	@rm -rf $(ark_client_dir) $(indexer_client_dir)
	@echo "Generating rest client from stub..."
	@mkdir -p $(ark_client_dir) $(indexer_client_dir)
	@$(SWAGGER) generate -i api-spec/openapi/swagger/ark/v1/service.openapi.json --skip-validate-spec -g go -o pkg/client-lib/$(ark_client_dir) --global-property apis,models,apiDocs=false,apiTests=false,modelDocs=false,modelTests=false,supportingFiles=utils.go:configuration.go:client.go -t pkg/client-lib/.openapi/templates
	@$(SWAGGER) generate -i api-spec/openapi/swagger/ark/v1/indexer.openapi.json --skip-validate-spec -g go -o pkg/client-lib/$(indexer_client_dir) --global-property apis,models,apiDocs=false,apiTests=false,modelDocs=false,modelTests=false,supportingFiles=utils.go:configuration.go:client.go -t pkg/client-lib/.openapi/templates