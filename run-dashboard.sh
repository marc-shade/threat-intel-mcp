#!/bin/bash
set -a
source "$(dirname "$0")/.env"
set +a
exec python -m world_intel_mcp.dashboard.app
