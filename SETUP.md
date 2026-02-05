# ShadowHawk Platform Setup Guide

## Prerequisites

- Python 3.10 or higher
- Poetry (for dependency management)
- Redis (for response caching, optional)
- OpenAI API key or Anthropic API key

## Installation

### 1. Install Poetry (if not already installed)

```bash
curl -sSL https://install.python-poetry.org | python3 -
```

### 2. Install Dependencies

```bash
poetry install
```

### 3. Configure Environment

Copy the example environment file:

```bash
cp .env.example .env
```

Edit `.env` and add your API keys:

```env
# For OpenAI
OPENAI_API_KEY=sk-your-key-here
LLM_PROVIDER=openai

# Or for Anthropic
ANTHROPIC_API_KEY=sk-ant-your-key-here
LLM_PROVIDER=anthropic
```

### 4. Setup Redis (Optional, for Caching)

#### Using Docker:

```bash
docker run -d -p 6379:6379 redis:latest
```

#### Using system package manager:

**Ubuntu/Debian:**
```bash
sudo apt-get install redis-server
sudo systemctl start redis
```

**macOS:**
```bash
brew install redis
brew services start redis
```

If you don't want to use Redis caching, the system will automatically disable caching and fall back to direct LLM calls.

## Running Tests

### Run all tests:

```bash
poetry run pytest
```

### Run with coverage:

```bash
poetry run pytest --cov=shadowhawk --cov-report=html
```

### Run specific test suites:

```bash
# Integration tests only
poetry run pytest tests/integration/

# Unit tests only
poetry run pytest tests/unit/
```

## Running Examples

```bash
poetry run python examples/basic_usage.py
```

## Project Structure

```
shadowhawk/
├── src/shadowhawk/
│   ├── application/
│   │   └── engines/
│   │       └── ai_analysis.py          # Main AI analysis engine
│   └── infrastructure/
│       └── ai/
│           ├── llm_client.py            # LLM client wrapper
│           ├── prompt_library.py        # Prompt management
│           └── response_cache.py        # Response caching
├── config/
│   └── prompts/                         # Prompt templates
│       ├── threat_explanation.yaml
│       ├── remediation_prioritization.yaml
│       ├── attack_path.yaml
│       ├── executive_summary.yaml
│       └── mitre_context.yaml
├── tests/
│   ├── integration/                     # Integration tests
│   └── unit/                            # Unit tests
└── examples/                            # Usage examples
```

## Configuration Options

### LLM Provider Settings

| Variable | Description | Default |
|----------|-------------|---------|
| `LLM_PROVIDER` | Provider to use (openai/anthropic) | `openai` |
| `OPENAI_API_KEY` | OpenAI API key | Required if using OpenAI |
| `OPENAI_MODEL` | OpenAI model name | `gpt-4-turbo-preview` |
| `ANTHROPIC_API_KEY` | Anthropic API key | Required if using Anthropic |
| `ANTHROPIC_MODEL` | Anthropic model name | `claude-3-opus-20240229` |
| `OPENAI_MAX_TOKENS` | Max tokens per request | `4096` |
| `OPENAI_TEMPERATURE` | Sampling temperature | `0.3` |

### Caching Settings

| Variable | Description | Default |
|----------|-------------|---------|
| `REDIS_URL` | Redis connection URL | `redis://localhost:6379` |
| `REDIS_CACHE_TTL` | Cache TTL in seconds | `3600` |

### Cost Tracking

| Variable | Description | Default |
|----------|-------------|---------|
| `ENABLE_COST_TRACKING` | Enable cost tracking | `true` |
| `COST_ALERT_THRESHOLD` | Alert threshold in USD | `100.00` |

## Usage

### Basic Threat Analysis

```python
from shadowhawk.application.engines.ai_analysis import AIAnalysisEngine

engine = AIAnalysisEngine()

result = await engine.analyze_threat(
    threat_id="CVE-2024-1234",
    threat_type="SQL Injection",
    severity="Critical",
    affected_systems="Production Database",
    threat_details="Details about the threat...",
)

print(result.executive_summary)
print(result.immediate_actions)
```

### Remediation Prioritization

```python
findings = [
    {"id": "VULN-001", "severity": "critical", "type": "SQL Injection"},
    {"id": "VULN-002", "severity": "high", "type": "XSS"},
]

plan = await engine.prioritize_remediation(
    findings=findings,
    industry="Healthcare",
    critical_assets="Patient Database",
    compliance_requirements="HIPAA, PCI-DSS",
)

print(plan.priority_1)  # Immediate actions
print(plan.priority_2)  # Urgent actions
```

### Get Statistics

```python
stats = engine.get_stats()
print(f"Total cost: ${stats['llm']['total_cost']:.4f}")
print(f"Cache hit rate: {stats['cache']['hit_rate_percent']:.1f}%")
```

## Cost Management

The platform includes comprehensive cost tracking:

1. **Real-time tracking**: Monitor token usage and costs per request
2. **Caching**: Reduce duplicate API calls with Redis caching
3. **Statistics**: Get detailed usage and cost reports

### Typical Costs (as of 2024)

| Model | Prompt Cost | Completion Cost | Typical Analysis Cost |
|-------|-------------|-----------------|----------------------|
| GPT-4 Turbo | $0.01/1K tokens | $0.03/1K tokens | $0.05-0.15 |
| Claude 3 Opus | $0.015/1K tokens | $0.075/1K tokens | $0.10-0.25 |
| Claude 3 Sonnet | $0.003/1K tokens | $0.015/1K tokens | $0.02-0.05 |

With caching enabled, expect 60-80% cost reduction for repeated analyses.

## Troubleshooting

### Redis Connection Issues

If Redis is not available, the system automatically disables caching:

```
WARNING: redis_connection_failed, fallback: caching_disabled
```

This is normal and the system will continue to work without caching.

### API Key Issues

Ensure your API keys are correctly set:

```bash
# Test OpenAI connection
python -c "import openai; openai.OpenAI(api_key='your-key').models.list()"

# Test Anthropic connection
python -c "import anthropic; anthropic.Anthropic(api_key='your-key').models.list()"
```

### Rate Limiting

The LLM client includes automatic retry with exponential backoff for rate limit errors.

## Security Best Practices

1. **Never commit API keys**: Use `.env` file (already in `.gitignore`)
2. **Rotate keys regularly**: Set up key rotation schedule
3. **Monitor costs**: Set up alerts for unusual usage
4. **Restrict access**: Use environment-specific API keys
5. **Enable caching**: Reduce unnecessary API calls

## Support

For issues, questions, or contributions:
- Check existing tests for usage examples
- Review prompt templates in `config/prompts/`
- See `examples/` directory for complete examples
