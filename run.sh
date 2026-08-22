#!/bin/sh
cd "$(dirname "$0")"
exec node mcp/server.mjs
