#!/usr/bin/env bash

echo "PATH: $PATH"

# Esegue ESLint tramite Docker Compose
docker compose run --rm eslint
