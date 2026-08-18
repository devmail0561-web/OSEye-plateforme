#!/bin/sh
# Docker entrypoint — lit les fichiers secrets Docker et les exporte comme
# variables d'environnement. Supporte le pattern *_FILE : si OSEYE_FOO_FILE
# est défini et pointe vers un fichier lisible, son contenu est exporté en
# OSEYE_FOO.
set -e

for var in \
    OSEYE_SECRET_KEY \
    OSEYE_CHECKPOINT_HMAC_KEY \
    OSEYE_ADMIN_PASSWORD \
    OSEYE_ANALYST_PASSWORD; do
    file_var="${var}_FILE"
    # eval pour lire la valeur de la variable dont le nom est dans $file_var
    eval "file_val=\${${file_var}:-}"
    if [ -n "$file_val" ] && [ -f "$file_val" ]; then
        val=$(cat "$file_val")
        export "${var}=${val}"
        unset "$file_var"
    fi
done

# Construire OSEYE_DB_URL depuis le mot de passe secret
if [ -n "${OSEYE_DB_PASSWORD_FILE:-}" ] && [ -f "$OSEYE_DB_PASSWORD_FILE" ]; then
    db_pass=$(cat "$OSEYE_DB_PASSWORD_FILE")
    export OSEYE_DB_URL="postgresql+asyncpg://oseye:${db_pass}@postgres:5432/oseye"
    unset OSEYE_DB_PASSWORD_FILE
fi

# Construire OSEYE_REDIS_URL depuis le mot de passe secret
if [ -n "${OSEYE_REDIS_PASSWORD_FILE:-}" ] && [ -f "$OSEYE_REDIS_PASSWORD_FILE" ]; then
    redis_pass=$(cat "$OSEYE_REDIS_PASSWORD_FILE")
    export OSEYE_REDIS_URL="redis://:${redis_pass}@redis:6379/0"
    unset OSEYE_REDIS_PASSWORD_FILE
fi

exec "$@"
