#!/bin/bash

set -euo pipefail

go test -cover -race -v ./...