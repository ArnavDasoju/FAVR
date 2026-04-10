#!/bin/bash
# FAVR - Start both API server and dashboard

echo "Starting FAVR..."
echo ""

# Start FastAPI backend
echo "[1/2] Starting API server on port 8000..."
python3 -m uvicorn favr.pipeline.server:app --host 0.0.0.0 --port 8000 &
API_PID=$!

# Wait for API to be ready
sleep 2

# Start dashboard
echo "[2/2] Starting dashboard on port 5173..."
cd dashboard && npm run dev &
DASH_PID=$!

echo ""
echo "FAVR is running!"
echo "  Dashboard: http://localhost:5173"
echo "  API:       http://localhost:8000"
echo "  API Docs:  http://localhost:8000/docs"
echo ""
echo "Press Ctrl+C to stop all services"

# Cleanup on exit
trap "kill $API_PID $DASH_PID 2>/dev/null" EXIT
wait
