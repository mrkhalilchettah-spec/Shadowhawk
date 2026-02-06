- Latest Release
- Version: **v1.0.0 – Technical Preview**
- Status: Pre-release
- Release page: https://github.com/mrkhalilchettah-spec/Shadowhawk/releases/tag/v1.0.0
  
# ShadowHawk Platform

**Enterprise-Grade Cyber Security Orchestration & Analysis Platform**

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-green.svg)](https://fastapi.tiangolo.com/)
[![Next.js](https://img.shields.io/badge/Next.js-14+-black.svg)](https://nextjs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0+-blue.svg)](https://www.typescriptlang.org/)

---

## 🚀 Overview

**ShadowHawk Platform** is a production-grade cybersecurity orchestration and analysis platform designed for **SOC teams**, **MSSPs**, and **professional pentest firms**. It combines advanced threat modeling, AI-powered analysis, and intelligent correlation engines to provide actionable security intelligence.

### 🎯 Target Audience
- **Security Operations Centers (SOCs)**
- **Managed Security Service Providers (MSSPs)**
- **Professional Penetration Testing Firms**
- **Enterprise Security Teams**
- **Cybersecurity Consultants**

---

## ✨ Key Features

### 🧠 **Core Intelligence Engines**

| Engine | Description | Status |
|--------|-------------|--------|
| **Threat Modeling** | Asset-based threat modeling with STRIDE classification and attack surface analysis | ✅ Production Ready |
| **Detection Logic** | Rule-based and ML-powered anomaly detection with false positive reduction | ✅ Production Ready |
| **MITRE ATT&CK Mapping** | NLP-based automatic mapping to MITRE ATT&CK techniques with confidence scoring | ✅ Production Ready |
| **Correlation Engine** | Graph-based multi-dimensional correlation for attack path reconstruction | ✅ Production Ready |
| **Risk Scoring** | Dynamic CVSS-based risk scoring with business impact modeling | ✅ Production Ready |
| **AI Analysis** | Real LLM integration for threat explanation and remediation prioritization | ✅ Production Ready |

### 🛡️ **Security & Infrastructure**

- **🔐 Enterprise Authentication**: JWT-based auth with RBAC (Role-Based Access Control)
- **📝 Comprehensive Audit Logging**: Append-only, tamper-aware audit trails
- **⚡ Rate Limiting**: API protection with configurable rate limits
- **🐳 Secure Sandboxing**: Docker + Firejail isolation for safe tool execution
- **🔒 Input Validation**: Strict Pydantic-based validation for all inputs
- **🌐 Multi-Tenant Ready**: Designed for SaaS deployment

### 🎨 **Professional Dashboard**

- **📊 Executive Dashboard**: C-level risk trends, compliance status, and KPIs
- **👨‍💻 SOC Analyst View**: Real-time alerts, findings, and quick actions
- **🗺️ MITRE ATT&CK Heatmap**: Interactive technique matrix with detection coverage
- **🔗 Correlation Timeline**: Visual attack path reconstruction
- **📈 Risk Management**: Prioritized remediation queue with ROI analysis
- **📄 Professional Reports**: Auto-generated PDF reports (technical + executive)

### 🤖 **AI-Powered Intelligence**

- **💬 Threat Explanation**: Business impact analysis in plain language
- **🎯 Remediation Prioritization**: Smart ordering based on risk and effort
- **🔍 Attack Path Reasoning**: Automated attack narrative generation
- **📊 Executive Summaries**: Non-technical summaries for management
- **💰 Cost Tracking**: Token usage monitoring and budget controls

---

## 🏗️ Architecture

ShadowHawk follows **Clean Architecture** principles with strict separation of concerns:

```
┌──────────────────────────────────────────────────────────┐
│                     API Layer (FastAPI)                   │
│   Routes • Middleware • Authentication • Rate Limiting    │
└────────────────────────┬─────────────────────────────────┘
                         │
┌────────────────────────▼─────────────────────────────────┐
│                  Application Layer                        │
│                                                            │
│  ┌─────────────────┐  ┌─────────────────┐  ┌──────────┐ │
│  │ Threat Modeling │  │ MITRE Mapping   │  │ AI Engine│ │
│  └─────────────────┘  └─────────────────┘  └──────────┘ │
│  ┌─────────────────┐  ┌─────────────────┐  ┌──────────┐ │
│  │ Detection Logic │  │ Correlation     │  │ Risk     │ │
│  └─────────────────┘  └─────────────────┘  └──────────┘ │
└────────────────────────┬─────────────────────────────────┘
                         │
┌────────────────────────▼─────────────────────────────────┐
│                    Domain Layer                           │
│  Asset • Threat • Finding • Detection • Risk • User       │
└────────────────────────┬─────────────────────────────────┘
                         │
┌────────────────────────▼─────────────────────────────────┐
│                Infrastructure Layer                       │
│  Database • Security • Sandbox • AI • Cache • External    │
└──────────────────────────────────────────────────────────┘
```

### 📂 Project Structure

```
shadowhawk/
├── src/shadowhawk/           # Backend (Python/FastAPI)
│   ├── api/                  # API routes & middleware
│   ├── application/          # Business logic & engines
│   │   └── engines/          # Core analysis engines
│   ├── domain/               # Domain models
│   │   └── models/           # Entity definitions
│   ├── infrastructure/       # External integrations
│   │   ├── ai/               # LLM client & prompts
│   │   ├── security/         # Auth, RBAC, audit
│   │   └── sandbox/          # Docker/Firejail
│   └── ml/                   # Machine learning
│       ├── training/         # Model training
│       ├── inference/        # Predictions
│       └── data_prep/        # Feature engineering
├── frontend/                 # Frontend (Next.js/TypeScript)
│   └── src/
│       ├── app/              # Pages (App Router)
│       ├── components/       # React components
│       ├── lib/              # Utilities & API client
│       └── hooks/            # Custom React hooks
├── tests/                    # Test suite
│   ├── unit/                 # Unit tests
│   └── integration/          # Integration tests
├── config/                   # Configuration files
│   └── prompts/              # AI prompt templates
├── docs/                     # Documentation
├── scripts/                  # Utility scripts
└── examples/                 # Usage examples
```

---

## 🚀 Quick Start

### Prerequisites

- **Python**: 3.11 or higher
- **Node.js**: 18 or higher
- **Docker**: 20.10 or higher (for sandboxing)
- **Redis**: 7.0 or higher (for caching)
- **PostgreSQL**: 14 or higher (recommended for production)

### 1️⃣ Clone the Repository

```bash
git clone https://github.com/yourusername/shadowhawk.git
cd shadowhawk
```

### 2️⃣ Backend Setup

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Copy environment template
cp .env.example .env

# Edit .env with your configuration
# Required: DATABASE_URL, REDIS_URL, OPENAI_API_KEY or ANTHROPIC_API_KEY

# Initialize database
python scripts/init_db.py

# Run backend
uvicorn src.shadowhawk.api.main:app --reload --port 8000
```

### 3️⃣ Frontend Setup

```bash
cd frontend

# Install dependencies
npm install

# Copy environment template
cp .env.example .env.local

# Edit .env.local
# NEXT_PUBLIC_API_URL=http://localhost:8000

# Run development server
npm run dev
```

### 4️⃣ Access the Platform

- **Frontend Dashboard**: http://localhost:3000
- **API Documentation**: http://localhost:8000/docs
- **API Redoc**: http://localhost:8000/redoc

### Default Credentials (Development Only)

- **Username**: `admin@shadowhawk.local`
- **Password**: `ChangeMeInProduction!`

> ⚠️ **Security Warning**: Change default credentials immediately in production!

---

## 🔧 Configuration

### Environment Variables

#### Backend (.env)

```bash
# Database
DATABASE_URL=postgresql://user:password@localhost/shadowhawk

# Redis (for caching & rate limiting)
REDIS_URL=redis://localhost:6379/0

# Security
JWT_SECRET=your-super-secret-jwt-key-change-this
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=60

# AI Integration (choose one or both)
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...

# AI Settings
AI_PROVIDER=openai  # or 'anthropic'
AI_MODEL=gpt-4-turbo
AI_MAX_TOKENS=4000
AI_TEMPERATURE=0.3

# Cost Controls
AI_MONTHLY_BUDGET=1000.00
AI_DAILY_LIMIT=100.00

# Sandbox
DOCKER_ENABLED=true
FIREJAIL_ENABLED=true

# CORS
ALLOWED_ORIGINS=http://localhost:3000,https://yourdomain.com

# Rate Limiting
RATE_LIMIT_ENABLED=true
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_WINDOW=60
```

#### Frontend (.env.local)

```bash
NEXT_PUBLIC_API_URL=http://localhost:8000
NEXT_PUBLIC_WS_URL=ws://localhost:8000/ws
```

---

## 📚 Documentation

| Document | Description |
|----------|-------------|
| [**ARCHITECTURE.md**](./ARCHITECTURE.md) | Detailed architecture overview |
| [**SETUP.md**](./SETUP.md) | Comprehensive setup guide |
| [**CONTRIBUTING.md**](./CONTRIBUTING.md) | Contribution guidelines |
| [**QUICKSTART.md**](./QUICKSTART.md) | Quick start tutorial |
| [**API Documentation**](http://localhost:8000/docs) | Interactive API docs (Swagger) |

---

## 🧪 Testing

### Run All Tests

```bash
# Backend tests
pytest tests/ -v --cov=src/shadowhawk

# Frontend tests
cd frontend && npm test

# E2E tests
cd frontend && npm run test:e2e
```

### Run Specific Test Suites

```bash
# Unit tests only
pytest tests/unit/ -v

# Integration tests
pytest tests/integration/ -v

# Specific engine
pytest tests/unit/test_threat_modeling.py -v
```

### Test Coverage

```bash
pytest tests/ --cov=src/shadowhawk --cov-report=html
# View coverage report: open htmlcov/index.html
```

---

## 🐳 Docker Deployment

### Using Docker Compose (Recommended)

```bash
# Build and start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

### Manual Docker Build

```bash
# Build backend image
docker build -t shadowhawk-backend .

# Run backend container
docker run -d \
  --name shadowhawk-api \
  -p 8000:8000 \
  -e DATABASE_URL=postgresql://... \
  -e REDIS_URL=redis://... \
  shadowhawk-backend

# Build frontend image
cd frontend
docker build -t shadowhawk-frontend .

# Run frontend container
docker run -d \
  --name shadowhawk-web \
  -p 3000:3000 \
  -e NEXT_PUBLIC_API_URL=http://localhost:8000 \
  shadowhawk-frontend
```

---

## 🔌 API Usage Examples

### Authentication

```bash
# Login
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin@shadowhawk.local", "password": "ChangeMeInProduction!"}'

# Response: {"access_token": "eyJ...", "token_type": "bearer"}
```

### Create Asset

```bash
curl -X POST http://localhost:8000/api/v1/threat-modeling/assets \
  -H "Authorization: Bearer eyJ..." \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Production API",
    "asset_type": "application",
    "criticality": "high",
    "description": "Main REST API"
  }'
```

### Run Threat Modeling

```bash
curl -X POST http://localhost:8000/api/v1/threat-modeling/analyze/ASSET_ID \
  -H "Authorization: Bearer eyJ..."
```

### Generate Report

```bash
curl -X POST http://localhost:8000/api/v1/reports/generate \
  -H "Authorization: Bearer eyJ..." \
  -H "Content-Type: application/json" \
  -d '{
    "assessment_id": "ASSESSMENT_ID",
    "report_type": "executive"
  }' \
  --output report.pdf
```

---

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](./CONTRIBUTING.md) for details.

### Development Workflow

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Code Style

- **Python**: Follow PEP 8, use `black` for formatting
- **TypeScript**: Follow Airbnb style guide, use `prettier`
- **Commits**: Use conventional commits (feat, fix, docs, etc.)

---

## 📊 Roadmap

### ✅ Version 1.0 (Current)
- [x] Core engines implementation
- [x] AI integration
- [x] Professional dashboard
- [x] Authentication & RBAC
- [x] PDF reporting
- [x] Docker deployment

### 🚧 Version 1.1 (In Progress)
- [ ] Advanced ML models for detection
- [ ] Real-time WebSocket integration
- [ ] Multi-language support (i18n)
- [ ] Enhanced threat intelligence feeds
- [ ] Custom detection rule builder UI

### 🔮 Future Versions
- [ ] Mobile app (iOS/Android)
- [ ] SIEM integrations (Splunk, ELK, QRadar)
- [ ] Compliance frameworks (ISO 27001, SOC 2)
- [ ] Advanced UEBA capabilities
- [ ] Kubernetes deployment
- [ ] Multi-tenancy (SaaS mode)
- [ ] API marketplace for plugins

---

## 🆘 Support

### Getting Help

- **Documentation**: Check the [docs/](./docs) folder
- **GitHub Issues**: [Report bugs or request features](https://github.com/yourusername/shadowhawk/issues)
- **Discussions**: [Ask questions](https://github.com/yourusername/shadowhawk/discussions)

### Commercial Support

For enterprise support, custom development, or consulting services, contact:
- **Email**: mr.khalilchettah@gmail.com
- **Website**: *********

---

## 📄 License

This project is licensed under the **Apache License 2.0** - see the [LICENSE](./LICENSE) file for details.

### Third-Party Licenses

ShadowHawk uses various open-source libraries. See [THIRD_PARTY_LICENSES.md](./docs/THIRD_PARTY_LICENSES.md) for details.

---

## 🙏 Acknowledgments

- **MITRE Corporation** for the ATT&CK® framework
- **FastAPI** community for the excellent web framework
- **Next.js** team for the React framework
- **OpenAI** and **Anthropic** for LLM APIs
- All contributors and supporters of this project

---

## 👨‍💻 Author

**Khalil Chettah**
- GitHub: [@khalilchettah](https://github.com/khalilchettah)
- LinkedIn: [Khalil Chettah](https://linkedin.com/in/khalilchettah)
- Email: mr.khalilchettah@gmail.com

---

## ⭐ Show Your Support

If you find ShadowHawk useful, please consider:
- ⭐ Starring the repository
- 🐛 Reporting bugs
- 💡 Suggesting new features
- 📢 Sharing with your network

---

**Built with  Mr.khalil for the cybersecurity community**

*ShadowHawk Platform - Making cybersecurity intelligence accessible and actionable*
