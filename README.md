# Self-Healing Systems

Python FastAPI backend + React/TypeScript dashboard. The backend monitors services, detects bugs,
runs an automatic fix (Detect, Diagnose, Fix, Verify) and pushes live state and alerts over WebSocket.
Incidents are saved in SQLite, and the dashboard needs a login.

## Run with Docker (one command)
    cp .env.example .env     # then edit the password and secret
    docker compose up --build
Open http://localhost:8080 and log in. Without a .env file the login is admin / admin123, so change it before sharing.

## Run without Docker
Backend:  cd backend && pip install -r requirements.txt && uvicorn main:app --port 8000
Frontend: cd frontend && npm install && npm run dev      (open http://localhost:5173)

## Websites
Use the Websites panel to add any web address. It is checked every 15 seconds for status, speed and uptime. When a site goes down you get an alert and an incident is saved. If you add a restart link (a URL that restarts your site), it is called automatically.

## API
POST /api/login, GET /api/state, GET /api/incidents, POST /api/sites, DELETE /api/sites/{id}, POST /api/inject, POST /api/auto/{true|false}, WebSocket /ws?token=...
All except login need the login token. Data is stored in the file set by DB_PATH (a Docker volume in Compose).

## Make it real
- Replace the simulated health values in monitor() (backend/main.py) with real checks.
- Put real recovery actions (restart container, roll back, clear cache) inside apply_fix().