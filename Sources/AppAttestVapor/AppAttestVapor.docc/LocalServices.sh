# Start PostgreSQL and Valkey for local development.
# Any local host setup is acceptable as long as values match DATABASE_URL and valkey address.

# PostgreSQL
createdb -h 127.0.0.1 -U postgres app_attest

# Valkey
valkey-server --port 6379 --daemonize yes

# Or via docker:
# docker run --rm --name app-attest-redis -p 6379:6379 valkey/valkey:8.0-alpine
