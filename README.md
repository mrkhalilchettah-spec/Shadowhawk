# ShadowHawk Platform

**Enterprise-Grade Cyber Security Platform**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-green.svg)](https://fastapi.tiangolo.com/)

## Overview

ShadowHawk is an enterprise-grade cybersecurity platform designed for comprehensive threat detection, analysis, and reporting. Built with clean architecture principles, it provides advanced threat modeling, detection logic, MITRE ATT&CK mapping, correlation analysis, and risk scoring capabilities.

### Key Features

- **🎯 Threat Modeling Engine**: Asset-based threat modeling with STRIDE classification
- **🔍 Detection Logic Engine**: Rule-based detection with multi-format normalization
- **🗺️ MITRE ATT&CK Mapping**: Automatic mapping of findings to MITRE ATT&CK framework
- **🔗 Correlation Engine**: Time-based and multi-tool correlation of security events
- **📊 Risk Scoring Engine**: CVSS-based scoring with contextual risk assessment
- **🔒 Secure Sandboxing**: Docker and Firejail-based isolation for secure tool execution
- **🤖 AI Integration**: LLM-powered threat explanation and analysis
- **📄 Professional Reporting**: PDF generation with comprehensive security reports
- **🛡️ Enterprise Security**: Full authentication, RBAC, audit logging, and rate limiting

## Architecture

ShadowHawk follows clean architecture principles with clear separation of concerns:

```
┌─────────────────────────────────────────────────────────┐
│                      API Layer                          │
│  (FastAPI Routes, Middleware, Request/Response)         │
└─────────────────┬───────────────────────────────────────┘
                  │
┌─────────────────▼───────────────────────────────────────┐
│                 Application Layer                       │
│  (Use Cases, Engine Orchestration, Business Logic)      │
│                                                          │
│  • Threat Modeling Engine    • Risk Scoring Engine      │
│  • Detection Logic Engine     • Correlation Engine      │
│  • MITRE ATT&CK Engine        • AI Analysis Engine      │
└─────────────────┬───────────────────────────────────────┘
                  │
┌─────────────────▼───────────────────────────────────────┐
│                   Domain Layer                          │
│  (Entities, Value Objects, Domain Services)             │
│                                                          │
│  • Threat Models    • Detections    • Findings          │
│  • Assets           • Risks         • Reports           │
└─────────────────┬───────────────────────────────────────┘
                  │
┌─────────────────▼───────────────────────────────────────┐
│               Infrastructure Layer                      │
│  (Persistence, External Services, Security)             │
│                                                          │
│  • Database         • Docker Sandbox    • Auth/RBAC     │
│  • File Storage     • Firejail          • Audit Logs    │
│  • LLM Integration  • Rate Limiting     • Encryption    │
└─────────────────────────────────────────────────────────┘
```

## Project Structure

```
shadowhawk/
├── src/shadowhawk/
│   ├── domain/                  # Domain layer (entities, value objects)
│   │   ├── models/              # Domain models
│   │   ├── services/            # Domain services
│   │   └── repositories/        # Repository interfaces
│   ├── application/             # Application layer (use cases, engines)
│   │   ├── engines/             # Core security engines
│   │   │   ├── threat_modeling.py
│   │   │   ├── detection_logic.py
│   │   │   ├── mitre_attack.py
│   │   │   ├── correlation.py
│   │   │   ├── risk_scoring.py
│   │   │   └── ai_analysis.py
│   │   └── use_cases/           # Application use cases
│   ├── infrastructure/          # Infrastructure layer
│   │   ├── persistence/         # Database implementations
│   │   ├── external/            # External service integrations
│   │   ├── security/            # Auth, RBAC, encryption
│   │   └── sandbox/             # Docker and Firejail sandboxing
│   └── api/                     # API layer (FastAPI)
│       ├── routes/              # API routes
│       ├── middleware/          # Middleware (auth, logging, rate limiting)
│       └── schemas/             # Request/response schemas
├── tests/
│   ├── unit/                    # Unit tests
│   └── integration/             # Integration tests
├── docs/                        # Additional documentation
├── config/                      # Configuration files
└── scripts/                     # Utility scripts
```

## Getting Started

### Prerequisites

- Python 3.11+
- Docker (for sandboxing)
- Firejail (optional, for additional security)
- PostgreSQL or SQLite (for persistence)

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd shadowhawk
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Set up environment variables:
```bash
cp .env.example .env
# Edit .env with your configuration
```

5. Initialize the database:
```bash
python scripts/init_db.py
```

6. Run the application:
```bash
uvicorn src.shadowhawk.api.main:app --reload
```

The API will be available at `http://localhost:8000`

### Docker Deployment

```bash
docker-compose up -d
```

## Configuration

Configuration is managed through environment variables and YAML files:

- `.env` - Environment-specific configuration
- `config/default.yaml` - Default configuration
- `config/production.yaml` - Production configuration

Key configuration options:

```yaml
security:
  secret_key: "your-secret-key"
  algorithm: "HS256"
  access_token_expire_minutes: 30

database:
  url: "postgresql://user:password@localhost/shadowhawk"

sandbox:
  docker_enabled: true
  firejail_enabled: true
  timeout: 300

ai:
  provider: "openai"
  model: "gpt-4"
  api_key: "your-api-key"
```

## API Documentation

Once running, interactive API documentation is available at:

- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

### Authentication

ShadowHawk uses JWT-based authentication. To authenticate:

1. Register a user:
```bash
POST /api/v1/auth/register
{
  "username": "admin",
  "email": "admin@example.com",
  "password": "secure_password"
}
```

2. Login to get a token:
```bash
POST /api/v1/auth/login
{
  "username": "admin",
  "password": "secure_password"
}
```

3. Use the token in subsequent requests:
```bash
Authorization: Bearer <your-token>
```

### Role-Based Access Control (RBAC)

Roles:
- **Admin**: Full system access
- **Analyst**: Read/write access to analyses and reports
- **Viewer**: Read-only access

## Core Engines

### Threat Modeling Engine

Asset-based threat modeling with STRIDE classification:

```python
POST /api/v1/threat-modeling/analyze
{
  "assets": [
    {
      "name": "Web Application",
      "type": "application",
      "criticality": "high"
    }
  ]
}
```

### Detection Logic Engine

Rule-based detection with normalization:

```python
POST /api/v1/detection/analyze
{
  "logs": [...],
  "rules": [...]
}
```

### MITRE ATT&CK Mapping

Automatic mapping of findings to MITRE ATT&CK framework:

```python
POST /api/v1/mitre/map
{
  "finding": "Suspicious PowerShell execution",
  "indicators": [...]
}
```

### Correlation Engine

Correlate events across time and tools:

```python
POST /api/v1/correlation/analyze
{
  "events": [...],
  "time_window": 300
}
```

### Risk Scoring Engine

CVSS-based scoring with contextual factors:

```python
POST /api/v1/risk/score
{
  "vulnerability": {...},
  "context": {...}
}
```

## Security Features

- **Authentication**: JWT-based authentication with refresh tokens
- **Authorization**: Role-based access control (RBAC)
- **Audit Logging**: Comprehensive audit trail of all actions
- **Rate Limiting**: Protection against abuse
- **Input Validation**: Strict validation of all inputs
- **Sandboxing**: Docker and Firejail isolation for tool execution
- **Encryption**: At-rest and in-transit encryption

## Testing

Run the test suite:

```bash
# All tests
pytest

# Unit tests only
pytest tests/unit/

# Integration tests only
pytest tests/integration/

# With coverage
pytest --cov=src/shadowhawk --cov-report=html
```

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Attribution

All source code files include proper attribution headers as per project guidelines.

## Support

For issues, questions, or contributions, please open an issue on the project repository.

## Roadmap

- [ ] Advanced ML-based anomaly detection
- [ ] Integration with major SIEM platforms
- [ ] Custom plugin system
- [ ] Multi-tenant support
- [ ] Real-time dashboard
- [ ] Automated response capabilities

---

**Built with ❤️ for the security community**
