version ?= latest
IMAGE = pyvaultone:$(version)
ENVS = -e VAULT_ONE_API_USERNAME -e VAULT_ONE_API_PASSWORD -e VAULT_ONE_API_BASE_URL
dockerrun = docker run $(ENVS) --rm $(IMAGE)

release:
	git tag -a $(version) -m "Generated release "$(version)
	git push origin $(version)

image:
	docker build -t $(IMAGE) .

shell: image
	docker run -ti --rm $(IMAGE) bash

check: image
	$(dockerrun) ./hack/check.sh $(parameters)

lint: image
	$(dockerrun) ./hack/lint.sh $(parameters)

check-integration: image
	docker-compose run $(ENVS) --rm pyvaultone ./hack/check-integration.sh $(parameters)

cleanup: 
	docker-compose down

coverage: image
	$(dockerrun) ./hack/check.sh --coverage

coverage-show: coverage
	xdg-open ./tests/coverage/index.html
