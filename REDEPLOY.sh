#!/bin/bash
set -e

echo "============================================"
echo "OSEye - Redéploiement complet avec nouveaux builds"
echo "============================================"
echo ""

# ========================================
# Étape 1 : Nettoyage
# ========================================
echo "📦 Étape 1/6 : Nettoyage de l'existant..."
echo ""

echo "→ Arrêt de l'agent..."
sudo systemctl stop oseye-agent 2>/dev/null || true
sudo systemctl disable oseye-agent 2>/dev/null || true

echo "→ Désinstallation du package agent..."
sudo dpkg -r oseye-agent 2>/dev/null || true

echo "→ Nettoyage des certificats et config..."
sudo rm -rf /etc/oseye/certs/*
sudo rm -f /etc/oseye/agent.env

echo "→ Arrêt des containers Docker..."
docker stop oseye-server oseye-nginx oseye-ui oseye-postgres oseye-redis 2>/dev/null || true
docker rm oseye-server oseye-nginx oseye-ui oseye-postgres oseye-redis 2>/dev/null || true

echo "✅ Nettoyage terminé"
echo ""

# ========================================
# Étape 2 : Installation agent
# ========================================
echo "📦 Étape 2/6 : Installation du nouveau package agent..."
echo ""

sudo dpkg -i dist/oseye-agent_0.2.0~alpha.1_amd64.deb

echo "✅ Agent installé"
echo ""

# ========================================
# Étape 3 : Lancement stack serveur
# ========================================
echo "🐳 Étape 3/6 : Lancement de la stack serveur..."
echo ""

echo "→ PostgreSQL..."
docker run -d \
  --name oseye-postgres \
  --network oseye-net \
  -e POSTGRES_DB=oseye \
  -e POSTGRES_USER=oseye \
  -e POSTGRES_PASSWORD=oseye123 \
  postgres:16-alpine >/dev/null

echo "→ Redis..."
docker run -d \
  --name oseye-redis \
  --network oseye-net \
  redis:7-alpine >/dev/null

echo "→ Attente démarrage PostgreSQL..."
sleep 5

echo "→ Serveur OSEye..."
docker run -d \
  --name oseye-server \
  --network oseye-net \
  -p 8000:8000 \
  -p 50051:50051 \
  -v ~/oseye-certs:/etc/oseye/certs:ro \
  -e OSEYE_DB_BACKEND=postgresql \
  -e OSEYE_DB_URL='postgresql+asyncpg://oseye:oseye123@oseye-postgres:5432/oseye' \
  -e OSEYE_BUS_BACKEND=redis \
  -e OSEYE_REDIS_URL='redis://oseye-redis:6379/0' \
  -e OSEYE_API_HOST=0.0.0.0 \
  -e OSEYE_API_PORT=8000 \
  -e 'OSEYE_API_CORS_ORIGINS=["http://localhost:5174","https://localhost:443","http://localhost:5173"]' \
  -e OSEYE_GRPC_PORT=50051 \
  -e OSEYE_GRPC_INSECURE_DEV=false \
  -e OSEYE_GRPC_TLS_CERT=/etc/oseye/certs/server.crt \
  -e OSEYE_GRPC_TLS_KEY=/etc/oseye/certs/server.key \
  -e OSEYE_SECRET_KEY=b358d401c19ead453311d83ff6af82ac \
  -e OSEYE_CHECKPOINT_HMAC_KEY=9539d1a0b9dba5f3f27120ca88da0d35fc40e22a7bc793029806ed2c60d74971 \
  -e OSEYE_ADMIN_PASSWORD=admin123 \
  -e OSEYE_ANALYST_PASSWORD=analyst123 \
  -e OSEYE_JWT_PRIVATE_KEY_PATH=/etc/oseye/certs/jwt_private.pem \
  -e OSEYE_JWT_PUBLIC_KEY_PATH=/etc/oseye/certs/jwt_public.pem \
  -e OSEYE_JWT_ACCESS_TOKEN_EXPIRE_MINUTES=60 \
  -e OSEYE_ED25519_PUBLIC_KEY=/etc/oseye/certs/enrollment_ed25519.pub \
  -e OSEYE_PLUGINS_DIR=/tmp/oseye-plugins \
  -e OSEYE_PLUGIN_IPC_SOCKET=/tmp/oseye-plugin.sock \
  -e OSEYE_DATA_DIR=/tmp/oseye-data \
  -e OSEYE_ML_MODEL_DIR=/tmp/oseye-data/ml \
  -e OSEYE_ENROLLMENT_CA_CERT_FILE=/etc/oseye/certs/ca.crt \
  -e OSEYE_ENROLLMENT_CA_KEY_FILE=/etc/oseye/certs/ca.key \
  -e OSEYE_LOG_LEVEL=info \
  -e OSEYE_TLS_CERT=/etc/oseye/certs/server.crt \
  -e OSEYE_TLS_KEY=/etc/oseye/certs/server.key \
  oseye-server:0.2.0-alpha.1 >/dev/null

echo "→ Attente démarrage serveur..."
sleep 8

echo "→ Nginx (HTTPS proxy)..."
docker run -d \
  --name oseye-nginx \
  --network oseye-net \
  -p 443:443 \
  -v ~/oseye-certs:/etc/nginx/certs:ro \
  -v ~/nginx-https.conf:/etc/nginx/conf.d/default.conf:ro \
  nginx:alpine >/dev/null

echo "→ UI..."
docker run -d \
  --name oseye-ui \
  --network oseye-net \
  -p 5174:5173 \
  oseye-ui:0.2.0-alpha.1 >/dev/null

echo "✅ Stack serveur lancée"
echo ""

# ========================================
# Étape 4 : Vérification stack
# ========================================
echo "✅ Étape 4/6 : Vérification de la stack..."
echo ""

docker ps --format "table {{.Names}}\t{{.Status}}"

echo ""
echo "→ Test API HTTPS..."
HTTP_CODE=$(curl -k -s -o /dev/null -w "%{http_code}" https://localhost:443/api/v1/health)
if [ "$HTTP_CODE" = "200" ]; then
  echo "✅ API HTTPS OK"
else
  echo "❌ API HTTPS failed (HTTP $HTTP_CODE)"
  exit 1
fi

echo ""

# ========================================
# Étape 5 : Enrollment agent
# ========================================
echo "🔐 Étape 5/6 : Enrollment de l'agent..."
echo ""
echo "⚠️  VOUS DEVEZ MAINTENANT LANCER MANUELLEMENT :"
echo ""
echo "sudo oseye-config enroll \\"
echo "  --server localhost:443 \\"
echo "  --token a047fe7ecb100b19e25ff5afb4288c0dae6907da6813aab0ce7fed062d6d0ffd \\"
echo "  --grpc-port 50051"
echo ""
echo "✨ Le nouveau oseye-config fixera automatiquement les permissions!"
echo ""
echo "Puis vérifiez :"
echo "  sudo systemctl status oseye-agent"
echo "  ls -la /etc/oseye/certs/  # Owner doit être oseye:oseye"
echo "  sudo journalctl -u oseye-agent -f"
echo ""

# ========================================
# Étape 6 : Accès UI
# ========================================
echo "🌐 Étape 6/6 : Accès à l'interface..."
echo ""
echo "→ UI disponible sur : http://localhost:5174"
echo "→ Login : admin / admin123"
echo "→ Vérifier dans Agents → virus-one doit apparaître avec status ✅ Connected"
echo ""
echo "============================================"
echo "Redéploiement terminé !"
echo "============================================"
