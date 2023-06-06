# VERSION defines the project version for the bundle.
# Update this value when you upgrade the version of your project.
# To re-generate a bundle for another specific version without changing the standard setup, you can:
# - use the VERSION as arg of the bundle target (e.g make bundle VERSION=0.0.2)
# - use environment variables to overwrite this value (e.g export VERSION=0.0.2)
VERSION ?= 0.1.3

# IMAGE_TAG_BASE defines the docker.io namespace and part of the image name for remote images.
# This variable is used to construct full image tags for bundle and catalog images.
#
# For example, running 'make bundle-build bundle-push catalog-build catalog-push' will build and push both
# disasterproject.com/openldap-operator-bundle:$VERSION and disasterproject.com/openldap-operator-catalog:$VERSION.
IMAGE_TAG_BASE ?= docker.io/aescanero/micropki

# Setting SHELL to bash allows bash commands to be executed by recipes.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

.PHONY: all
all: build

PLATFORMS ?= linux/arm64,linux/amd64
.PHONY: build
build: ## Build image with the micropki.
	podman build --platform=linux/arm64 --no-cache -t $(IMAGE_TAG_BASE):$(VERSION)-linux-arm64 .
	podman build --platform=linux/amd64 --no-cache -t $(IMAGE_TAG_BASE):$(VERSION)-linux-amd64 .
	podman push $(IMAGE_TAG_BASE):$(VERSION)-linux-arm64
	podman push $(IMAGE_TAG_BASE):$(VERSION)-linux-amd64
	podman manifest create $(IMAGE_TAG_BASE):$(VERSION) \
  		$(IMAGE_TAG_BASE):$(VERSION)-linux-arm64 \
  		$(IMAGE_TAG_BASE):$(VERSION)-linux-amd64
	podman manifest push $(IMAGE_TAG_BASE):$(VERSION) docker://$(IMAGE_TAG_BASE):$(VERSION)
	podman manifest rm $(IMAGE_TAG_BASE):$(VERSION)
