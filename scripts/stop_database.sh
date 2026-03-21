#!/bin/bash
# Stop PostgreSQL database for Vigil SOC v2.0

set -e

echo "=================================================="
echo "Vigil SOC v2.0 - Database Shutdown"
echo "=================================================="

if ! docker compose version &> /dev/null; then
    echo "❌ Docker Compose V2 not available (need \`docker compose\`)"
    exit 1
fi

# Stop containers
echo "Stopping PostgreSQL..."
cd docker
docker compose stop postgres
cd ..

echo ""
echo "✓ Database stopped"
echo ""
echo "To start: ./scripts/start_database.sh"
echo "To remove: cd docker && docker compose down -v"
echo ""

