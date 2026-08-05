#!/bin/bash

echo "========================================================"
echo "      Threat Detection Platform - Integrated Starter"
echo "========================================================"

# Navigate to project root
cd "$(dirname "$0")"

# 1. Stop host services if running to allow docker port binding
echo "[*] Ensuring database ports are free (stopping host PostgreSQL/Redis)..."
sudo systemctl stop postgresql redis-server 2>/dev/null || true

# 2. Start PostgreSQL and Redis Docker containers
echo "[*] Booting PostgreSQL and Redis Docker containers..."
if docker start threat-detector-postgres threat-detector-redis 2>/dev/null; then
    echo "[+] Docker containers threat-detector-postgres & threat-detector-redis started."
else
    echo "[!] Docker containers not found. Falling back to host services..."
    sudo systemctl start postgresql
    sudo systemctl start redis-server || redis-server --daemonize yes
fi

# 2. Start Backend FastAPI
echo "[*] Starting FastAPI Backend on port 8000..."
./venv/bin/uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 > backend.log 2>&1 &
BACKEND_PID=$!

# 3. Start Celery Worker
echo "[*] Starting Celery Worker..."
./venv/bin/celery -A backend.app.worker.celery_app worker --loglevel=info > celery.log 2>&1 &
CELERY_PID=$!

# 4. Start Frontend dev server
echo "[*] Starting Frontend Next.js Dev Server on port 3000..."
cd frontend
npm run dev > ../frontend.log 2>&1 &
FRONTEND_PID=$!
cd ..

# 5. Start Public Tunnel (Optional)
echo "[*] Starting Public HTTPS Tunnel (for mobile verification)..."
ssh -o StrictHostKeyChecking=no -R 80:localhost:8000 nokey@localhost.run > tunnel.log 2>&1 &
TUNNEL_PID=$!

echo "--------------------------------------------------------"
echo "All services started successfully in the background!"
echo "- FastAPI Backend: http://localhost:8000"
echo "- Frontend Client: http://localhost:3000"
echo ""
echo "👉 OPEN THE SOC DASHBOARD IN YOUR BROWSER:"
echo "   http://localhost:3000"
echo "--------------------------------------------------------"
echo ""
echo "To check the public HTTPS tunnel URL for your phone, run:"
echo "  grep -o 'https://.*lhr.life' tunnel.log"
echo ""
echo "To stop all services, press Ctrl+C in this terminal."
echo "--------------------------------------------------------"

# Keep script running to allow easy stopping with Ctrl+C
trap "echo 'Stopping all services...'; kill $BACKEND_PID $CELERY_PID $FRONTEND_PID $TUNNEL_PID; exit" INT
wait
