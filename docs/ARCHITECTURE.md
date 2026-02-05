<!-- 
ShadowHawk Platform Documentation - Architecture
Copyright (c) 2024 ShadowHawk Platform
Licensed under the MIT License
-->

# ShadowHawk Platform Architecture

## Overview

The ShadowHawk Platform is built using clean architecture principles with clear separation of concerns across four main layers.

## Architecture Layers

### 1. Domain Layer (`src/shadowhawk/domain/`)

The innermost layer containing business entities and core domain logic.

**Components:**
- **Models**: Core domain entities (Asset, Threat, Detection, Finding, Risk, User, AuditLog)
- **Services**: Domain services implementing business logic
- **Repositories**: Interface definitions for data access

**Key Principles:**
- No dependencies on outer layers
- Pure business logic
- Framework-independent
- Highly testable

### 2. Application Layer (`src/shadowhawk/application/`)

Contains application-specific business rules and use cases.

**Core Engines:**

1. **Threat Modeling Engine**
   - Asset-based threat modeling
   - STRIDE classification
   - Automated threat identification
   - Mitigation recommendations

2. **Detection Logic Engine**
   - Rule-based detection
   - Log normalization
   - Multi-format support (SIGMA, YARA, Custom)
   - Pattern matching

3. **MITRE ATT&CK Mapping Engine**
   - Automatic technique mapping
   - Tactic identification
   - Coverage analysis
   - ATT&CK matrix generation

4. **Correlation Engine**
   - Time-based correlation
   - Indicator-based correlation
   - Attack chain detection
   - Event grouping

5. **Risk Scoring Engine**
   - CVSS v3.1 calculation
   - Contextual risk assessment
   - Impact and likelihood scoring
   - Risk level classification

6. **AI Analysis Engine**
   - LLM-powered explanations
   - Threat analysis
   - Executive summaries
   - Remediation guidance

### 3. Infrastructure Layer (`src/shadowhawk/infrastructure/`)

Implements technical capabilities and external integrations.

**Components:**

1. **Security**
   - `AuthService`: JWT-based authentication
   - `RBACService`: Role-based access control
   - `AuditService`: Comprehensive audit logging

2. **Sandbox**
   - `DockerSandbox`: Container-based isolation
   - `FirejailSandbox`: Additional security layer

3. **Persistence**
   - Database implementations
   - Repository implementations
   - Data access layer

4. **External**
   - LLM integrations
   - External API clients
   - Third-party service integrations

### 4. API Layer (`src/shadowhawk/api/`)

Exposes functionality through REST API endpoints.

**Components:**
- **Routes**: API endpoints organized by feature
- **Middleware**: Cross-cutting concerns (auth, rate limiting, audit)
- **Schemas**: Request/response validation

## Data Flow

```
External Request
    ↓
API Layer (FastAPI)
    ↓
Middleware (Auth, Rate Limit, Audit)
    ↓
Application Layer (Engines & Use Cases)
    ↓
Domain Layer (Business Logic)
    ↓
Infrastructure Layer (Persistence, External Services)
    ↓
External Systems (Database, LLM APIs, etc.)
```

## Security Architecture

### Authentication Flow

1. User submits credentials
2. AuthService validates credentials
3. JWT tokens generated (access + refresh)
4. Tokens used for subsequent requests
5. AuditService logs authentication events

### Authorization Flow

1. JWT token validated
2. User roles extracted
3. RBACService checks permissions
4. Request allowed/denied based on permissions
5. Action logged in audit trail

### Sandboxing Architecture

**Multi-Layer Isolation:**

1. **Docker Layer**
   - Container isolation
   - Resource limits (CPU, memory)
   - Network isolation
   - Read-only filesystems

2. **Firejail Layer**
   - Additional sandboxing
   - Capability dropping
   - Seccomp filtering
   - Private home directories

## Engine Integration

Engines work together to provide comprehensive security analysis:

```
Asset → Threat Modeling → Threats
           ↓
Logs → Detection Logic → Detections
           ↓
Detections → MITRE Mapping → Techniques
           ↓
Detections → Correlation → Attack Chains
           ↓
Findings → Risk Scoring → Risks
           ↓
All Data → AI Analysis → Insights & Reports
```

## Scalability Considerations

1. **Horizontal Scaling**: API layer can be scaled independently
2. **Async Processing**: Long-running analyses can be queued
3. **Caching**: Redis for session and rate limit data
4. **Database**: PostgreSQL with connection pooling
5. **Load Balancing**: Multiple API instances behind load balancer

## Monitoring & Observability

1. **Logging**: Structured logging with correlation IDs
2. **Metrics**: Prometheus-compatible metrics
3. **Audit Trail**: Complete audit log of all actions
4. **Health Checks**: Endpoint for service health monitoring

## Extension Points

The architecture supports extensibility through:

1. **Custom Detection Rules**: Add new rule formats
2. **Additional Engines**: Plug in new analysis engines
3. **External Integrations**: Add new data sources
4. **Custom Reporting**: Extend report generation
5. **Plugin System**: Future support for custom plugins

## Best Practices

1. **Dependency Rule**: Dependencies point inward
2. **Interface Segregation**: Small, focused interfaces
3. **Dependency Injection**: Constructor injection preferred
4. **Testing**: Each layer tested independently
5. **Security First**: Security considerations at every layer

## Technology Stack

- **Language**: Python 3.11+
- **Web Framework**: FastAPI
- **Authentication**: JWT (python-jose)
- **Database**: PostgreSQL / SQLite
- **Containerization**: Docker
- **Sandboxing**: Docker + Firejail
- **AI/LLM**: OpenAI API / Anthropic
- **Testing**: Pytest
- **Documentation**: Markdown + OpenAPI

---

For implementation details, see the source code and inline documentation.
