# AWSP -- A2A Webhook Security Profile
# Convenience targets for running each reference impl's test suite locally.
# CI does not consume this file; it exists to give contributors a uniform
# entry point regardless of which language they touched.

.PHONY: conformance test-typescript test-python test-go test-java test-dotnet help

help:
	@echo "AWSP local targets:"
	@echo "  make conformance     -- run every reference impl's tests, print matrix"
	@echo "  make test-typescript -- TS reference impl only"
	@echo "  make test-python     -- Python reference impl only"
	@echo "  make test-go         -- Go reference impl only"
	@echo "  make test-java       -- Java reference impl only"
	@echo "  make test-dotnet     -- .NET reference impl only"

# Full conformance sweep. Delegates to scripts/conformance.sh which
# captures each port's result independently and exits non-zero only if
# at least one PRESENT toolchain failed (missing toolchains are SKIPped).
conformance:
	@bash scripts/conformance.sh

test-typescript:
	cd reference/typescript && npm ci && npm test

test-python:
	cd reference/python && pip install -e .[dev] && pytest

test-go:
	cd reference/go && go test ./...

test-java:
	cd reference/java && mvn -B test

test-dotnet:
	cd reference/dotnet && dotnet test --configuration Release
