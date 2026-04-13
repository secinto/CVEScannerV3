.PHONY: test lint clean install-deps docker bump-version release-notes tag release release-draft bump-and-release version help
.DEFAULT_GOAL := help

# Variables
PROJECT_NAME=CVEScannerV3
NSE_FILE=cvescannerv3.nse
PYTHON_DIR=extra
PYTHON_VERSION_FILE=extra/cvescan.py
# Version is read directly from the NSE file (format: N.N or N.N.N)
VERSION ?= $(shell grep '^version = ' $(NSE_FILE) | sed 's/version = "\(.*\)"/\1/' | tr -d ' ')
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
GIT_BRANCH := $(shell git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "master")
PYTHON ?= python3
DOCKER_IMAGE ?= cvescannerv3

TAG := v$(VERSION)
RELEASE_NOTES_DIR := release-notes
RELEASE_NOTES_FILE := $(RELEASE_NOTES_DIR)/$(TAG).md

# Install Python dependencies from extra/requirements.txt
install-deps:
	@echo "Installing Python dependencies..."
	$(PYTHON) -m pip install -r $(PYTHON_DIR)/requirements.txt
	@echo "Dependencies installed"

# Run Python unit tests
test:
	@echo "Running tests..."
	$(PYTHON) -m unittest discover -s $(PYTHON_DIR) -p 'test_*.py' -v
	@echo "Tests complete"

# Run linter on Python files
lint:
	@echo "Running linter..."
	@which ruff > /dev/null 2>&1 && ruff check $(PYTHON_DIR)/*.py || \
		(which flake8 > /dev/null 2>&1 && flake8 $(PYTHON_DIR)/*.py) || \
		echo "No linter found. Install ruff: pip install ruff"
	@echo "Lint complete"

# Remove Python cache files and build artifacts
clean:
	@echo "Cleaning..."
	find $(PYTHON_DIR) -type d -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true
	find $(PYTHON_DIR) -name '*.pyc' -delete 2>/dev/null || true
	@echo "Cleaned"

# Build Docker image
docker:
	@echo "Building Docker image $(DOCKER_IMAGE)..."
	docker build -t $(DOCKER_IMAGE) .
	@echo "Docker image $(DOCKER_IMAGE) built"

# Bump version in cvescannerv3.nse AND extra/cvescan.py.
# Auto-increment: bumps the minor component for N.N, or patch for N.N.N.
# Override with V=X.Y or V=X.Y.Z for an explicit version.
bump-version:
	@if [ -n "$(V)" ]; then \
		NEW_VERSION="$(V)"; \
	else \
		MAJOR=$$(echo "$(VERSION)" | cut -d. -f1); \
		MINOR=$$(echo "$(VERSION)" | cut -d. -f2); \
		PATCH_PART=$$(echo "$(VERSION)" | cut -d. -f3); \
		if [ -n "$$PATCH_PART" ]; then \
			NEW_VERSION="$$MAJOR.$$MINOR.$$((PATCH_PART + 1))"; \
		else \
			NEW_VERSION="$$MAJOR.$$((MINOR + 1))"; \
		fi; \
	fi; \
	if ! echo "$$NEW_VERSION" | grep -qE '^[0-9]{1,3}(\.[0-9]{1,3}){1,2}$$'; then \
		echo "Error: version '$$NEW_VERSION' must be N.N or N.N.N format"; exit 1; \
	fi; \
	V_MAJOR=$$(echo "$$NEW_VERSION" | cut -d. -f1); \
	V_MINOR=$$(echo "$$NEW_VERSION" | cut -d. -f2); \
	V_PATCH=$$(echo "$$NEW_VERSION" | cut -d. -f3); \
	if [ "$$V_MAJOR" -gt 100 ] || [ "$$V_MINOR" -gt 100 ]; then \
		echo "Error: version components must be 0-100, got '$$NEW_VERSION'"; exit 1; \
	fi; \
	if [ -n "$$V_PATCH" ] && [ "$$V_PATCH" -gt 100 ]; then \
		echo "Error: version components must be 0-100, got '$$NEW_VERSION'"; exit 1; \
	fi; \
	echo "Bumping version: $(VERSION) -> $$NEW_VERSION"; \
	sed -i.bak 's/^version = ".*"/version = "'"$$NEW_VERSION"'"/' $(NSE_FILE) && rm -f $(NSE_FILE).bak; \
	echo "  Updated $(NSE_FILE)"; \
	sed -i.bak 's/^VERSION = ".*"/VERSION = "'"$$NEW_VERSION"'"/' $(PYTHON_VERSION_FILE) && rm -f $(PYTHON_VERSION_FILE).bak; \
	echo "  Updated $(PYTHON_VERSION_FILE)"; \
	echo "Version bumped to $$NEW_VERSION"

# Generate version-specific release notes from git log since the last tag.
# Skips generation if the file already exists (preserves manual edits).
release-notes:
	@mkdir -p $(RELEASE_NOTES_DIR)
	@if [ -f "$(RELEASE_NOTES_FILE)" ]; then \
		echo "Release notes for $(TAG) already exist at $(RELEASE_NOTES_FILE) (skipping generation)"; \
	else \
		echo "Generating release notes for $(TAG)..."; \
		bash scripts/generate-release-notes.sh $(PROJECT_NAME) $(VERSION) > $(RELEASE_NOTES_FILE); \
		echo "Release notes written to $(RELEASE_NOTES_FILE)"; \
	fi
	@echo "---" && cat $(RELEASE_NOTES_FILE)

# Create and push an annotated git tag for the current VERSION
tag:
	@echo "Creating tag $(TAG)..."
	@if git rev-parse $(TAG) >/dev/null 2>&1; then \
		echo "Error: tag $(TAG) already exists. Run bump-version first."; exit 1; \
	fi
	git tag -a $(TAG) -m "Release $(TAG)"
	git push origin $(TAG)
	@echo "Tag $(TAG) created and pushed"

# Generate release notes, tag, and publish a GitHub release (no binary assets)
release: release-notes tag
	@echo "Creating GitHub release $(TAG)..."
	@which gh > /dev/null || (echo "Error: gh CLI not installed. Run: brew install gh"; exit 1)
	gh release create $(TAG) \
		--title "$(PROJECT_NAME) $(TAG)" \
		--notes-file $(RELEASE_NOTES_FILE)
	@echo "GitHub release $(TAG) created"

# Same as release but published as a draft for review before going public
release-draft: release-notes
	@echo "Creating draft GitHub release $(TAG)..."
	@which gh > /dev/null || (echo "Error: gh CLI not installed. Run: brew install gh"; exit 1)
	gh release create $(TAG) \
		--title "$(PROJECT_NAME) $(TAG)" \
		--notes-file $(RELEASE_NOTES_FILE) \
		--draft
	@echo "Draft release $(TAG) created"

# Bump version (minor by default, or V=X.Y[.Z]), generate notes, commit, push, then release
bump-and-release:
	@if [ -n "$(V)" ]; then \
		$(MAKE) bump-version V=$(V); \
	else \
		$(MAKE) bump-version; \
	fi
	$(MAKE) release-notes
	@NEW_VER=$$(grep '^version = ' $(NSE_FILE) | sed 's/version = "\(.*\)"/\1/' | tr -d ' '); \
	git add $(NSE_FILE) $(PYTHON_VERSION_FILE) release-notes/v$$NEW_VER.md; \
	git commit -m "chore: bump version to v$$NEW_VER"; \
	git push origin $(GIT_BRANCH)
	$(MAKE) release

# Show version
version:
	@echo "Version:    $(VERSION)"
	@echo "Tag:        $(TAG)"
	@echo "Git Commit: $(GIT_COMMIT)"
	@echo "Build Date: $(BUILD_DATE)"

# Show help
help:
	@echo "Makefile targets:"
	@echo "  make install-deps     - Install Python dependencies from extra/requirements.txt"
	@echo "  make test             - Run Python unit tests"
	@echo "  make lint             - Run linter on Python files (ruff or flake8)"
	@echo "  make clean            - Remove Python cache files"
	@echo "  make docker           - Build Docker image"
	@echo "  make version          - Show version information"
	@echo "  make bump-version     - Bump minor version (or V=X.Y[.Z] for explicit version)"
	@echo "  make release-notes    - Generate release-notes/v{VERSION}.md from git log (skips if exists)"
	@echo "  make tag              - Create and push git tag for current VERSION"
	@echo "  make release          - Generate notes, tag, and publish GitHub release"
	@echo "  make release-draft    - Generate notes and create a draft GitHub release"
	@echo "  make bump-and-release - Bump version, generate notes, commit, push, then release (V=X.Y[.Z] optional)"
	@echo "  make help             - Show this help"
