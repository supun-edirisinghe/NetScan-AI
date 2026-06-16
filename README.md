# 🔍 NetScan AI — Network Security Scanner

AI-powered network port scanner with risk analysis, interactive dashboard, and PDF reporting.

---

## 🚀 Quick Start — Docker (Easiest!) ⭐

> No need to install Python, Node.js, or PostgreSQL separately!

### Step 1 — Install Docker Desktop

👉 https://www.docker.com/products/docker-desktop

Download and install. Restart your computer after installation.

### Step 2 — Clone the Project

```bash
git clone https://github.com/Suppa08/netscan-ai.git
cd netscan-ai
```

### Step 3 — Build and Run

```bash
docker-compose up --build
```

First build takes 5-10 minutes. When complete you will see:

```
✅ PostgreSQL running
✅ Backend API running on port 8000
✅ Frontend running on port 80
```

### Step 4 — Add Demo Data (First time only)

Open a new terminal and run:

```bash
docker-compose exec backend python seed.py
```

Expected output:
```
Created admin user (password: admin123)
Created 3 demo scans
Seeding complete!
```

### Step 5 — Open in Browser

```
http://localhost
```

| Field    | Value    |
|----------|----------|
| Username | admin    |
| Password | admin123 |

### Stop the App

```bash
docker-compose down
```

### Start Again

```bash
docker-compose up
```

> No need for `--build` again unless you modify the source code.

---

## 🛠️ Manual Setup (Without Docker)

### Requirements

| Software   | Version | Download                          |
|------------|---------|-----------------------------------|
| Python     | 3.11+   | https://python.org/downloads      |
| Node.js    | v20+    | https://nodejs.org                |
| PostgreSQL | 16      | https://postgresql.org/download   |
| Git        | Latest  | https://git-scm.com/downloads     |

### Step 1 — Clone the Project

```bash
git clone https://github.com/Suppa08/netscan-ai.git
cd netscan-ai
```

### Step 2 — Database Setup

```bash
psql -U postgres
```

```sql
CREATE USER netscan WITH PASSWORD 'netscan_pass';
CREATE DATABASE netscan_db OWNER netscan;
GRANT ALL PRIVILEGES ON DATABASE netscan_db TO netscan;
\q
```

### Step 3 — Backend Setup

```bash
cd backend

# Create virtual environment
python -m venv venv

# Activate virtual environment (Windows)
venv\Scripts\activate

# Activate virtual environment (Mac/Linux)
source venv/bin/activate

# Install all dependencies
pip install -r requirements.txt --timeout 300

# Create environment config file
copy .env.example .env        # Windows
cp .env.example .env          # Mac/Linux

# Seed demo data into database
python seed.py

# Start the API server
uvicorn app.main:app --reload --port 8000
```

API documentation available at: http://localhost:8000/docs

### Step 4 — Frontend Setup

Open a new terminal:

```bash
cd frontend

# Create environment config file
copy .env.example .env        # Windows
cp .env.example .env          # Mac/Linux

# Install Node.js packages
npm install

# Start the development server
npm run dev
```

### Step 5 — Open in Browser

```
http://localhost:3000
```

Login credentials: `admin` / `admin123`

### Starting the App Every Day

**Terminal 1 — Backend:**
```bash
cd backend
venv\Scripts\activate
uvicorn app.main:app --reload --port 8000
```

**Terminal 2 — Frontend:**
```bash
cd frontend
npm run dev
```

---

## 📊 Tech Stack

| Layer    | Technology                        |
|----------|-----------------------------------|
| Frontend | React 18 + Recharts + Lucide      |
| Backend  | FastAPI (Python 3.11)             |
| Scanner  | asyncio sockets + python-nmap     |
| AI/ML    | Scikit-learn + TensorFlow (opt.)  |
| Database | PostgreSQL 16 (async SQLAlchemy)  |
| Auth     | JWT (python-jose + bcrypt)        |
| Reports  | ReportLab PDF                     |
| Deploy   | Docker Compose                    |

---

## 📊 Dashboard Features

- **Total Scans** — count of all historical scans
- **Hosts Scanned** — total unique IPs assessed
- **Open Ports** — cumulative count across all scans
- **High Risk Hosts** — hosts with critical or high risk score
- **Port Distribution** — bar chart of most commonly open ports
- **Risk Distribution** — pie chart breakdown by risk level
- **Scan Activity** — 30-day scan activity timeline
- **AI Recommendations** — prioritized security action list
- **PDF Export** — professional downloadable scan reports

---

## 🔒 Scan Types

| Type        | Description                          | Requires      |
|-------------|--------------------------------------|---------------|
| TCP Connect | Full 3-way handshake scan (default)  | Normal user   |
| SYN Scan    | Half-open, stealthier and faster     | Admin / Root  |
| UDP Scan    | UDP port detection, slower           | Admin / Root  |

---

## 🎯 Supported Scan Targets

```
127.0.0.1              # Your own computer (localhost)
192.168.1.1            # Your home router
192.168.1.0/24         # Your entire home network (CIDR range)
scanme.nmap.org        # Legal public practice target by Nmap
```

> ⚠️ Only scan networks you **own** or have **explicit written permission** to test!

---

## 🤖 AI / ML

### Default — Rule-Based Scoring (No training required)

Instant risk scoring using weighted port risk rules and expert security knowledge base.
Works out of the box with no model training needed.

### Train Scikit-learn Random Forest Model

```bash
cd backend

# Train using synthetic generated data
python ml_trainer.py

# Train using your real scan history from the database
python ml_trainer.py --use-db
```

### Train TensorFlow Neural Network (Optional)

```bash
pip install tensorflow
python ml_trainer.py
```

Trained models are saved to `backend/ml_models/` and automatically loaded by the API on startup.

---

## 🧪 Running Tests

```bash
cd backend
pip install pytest pytest-asyncio
pytest tests/ -v
```

---

## 📄 PDF Reports

Click **Export PDF** on any completed scan detail page. Reports include:

- Executive summary with overall risk metrics
- Top open ports distribution table
- AI security recommendations with CVE references
- Full scan metadata, target info, and duration

---

## 📁 Project Structure

```
netscan/
├── backend/
│   ├── app/
│   │   ├── api/          # FastAPI routers — Auth, Scans, Reports, Dashboard
│   │   ├── core/         # Config, Database connection, Security (JWT)
│   │   ├── ml/           # ML model inference loader
│   │   ├── models/       # SQLAlchemy ORM database models
│   │   └── services/     # Scanner engine, AI analyzer, PDF generator
│   ├── alembic/          # Database migration scripts
│   ├── tests/            # pytest unit tests
│   ├── ml_trainer.py     # Standalone ML model training script
│   ├── seed.py           # Demo data seeder script
│   └── requirements.txt  # Python dependencies
├── frontend/
│   └── src/
│       ├── pages/        # Dashboard, Scans, ScanDetail, NewScan, Login
│       └── utils/        # API client utility
├── docker-compose.yml    # Docker orchestration config
└── README.md
```

---

## ⚠️ Legal Notice

Only scan networks and systems you **own** or have **explicit written permission** to test.
Unauthorized port scanning may violate computer crime laws in your jurisdiction.

---

## 👨‍💻 Author

**Suppa08** — https://github.com/Suppa08/netscan-ai