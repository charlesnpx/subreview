#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VERSION="${SUBREVIEW_VERSION:-$(git -C "$SCRIPT_DIR" describe --tags --exact-match 2>/dev/null || true)}"
VERSION="${VERSION:-dev}"

export SUBREVIEW_REPO_ROOT="$SCRIPT_DIR"
exec go run -ldflags "-X main.Version=$VERSION" "$SCRIPT_DIR/cmd/subreview" install-skills "$@"
