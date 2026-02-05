# ShadowHawk Platform - Quick Start Guide

## 30-Second Setup

```bash
# 1. Clone and enter directory
cd shadowhawk-platform

# 2. Install dependencies
pip install -r requirements.txt
# OR
poetry install

# 3. Configure API key
cp .env.example .env
# Edit .env and add your OPENAI_API_KEY or ANTHROPIC_API_KEY

# 4. Run example
python examples/basic_usage.py
```

## 5-Minute Integration

```python
import asyncio
from shadowhawk.application.engines.ai_analysis import AIAnalysisEngine

async def main():
    # Initialize (reads from .env automatically)
    engine = AIAnalysisEngine()
    
    # Analyze a threat
    result = await engine.analyze_threat(
        threat_id="CVE-2024-1234",
        threat_type="SQL Injection",
        severity="Critical",
        affected_systems="Web Application",
        threat_details="SQL injection in login form"
    )
    
    # Use the results
    print(f"Summary: {result.executive_summary}")
    print(f"Actions: {result.immediate_actions}")
    
    # Check costs
    stats = engine.get_stats()
    print(f"Cost: ${stats['llm']['total_cost']:.4f}")

asyncio.run(main())
```

## Key Features at a Glance

| Feature | Description | Benefit |
|---------|-------------|---------|
| **Multi-LLM Support** | OpenAI GPT-4 & Anthropic Claude | Choose best model for your needs |
| **Cost Tracking** | Real-time token & cost monitoring | Control spending |
| **Response Caching** | Redis-based caching (60-80% savings) | Reduce API costs dramatically |
| **Prompt Library** | Version-controlled YAML templates | Consistent, maintainable prompts |
| **Structured Outputs** | Pydantic models for all responses | Type-safe, validated results |
| **Production Ready** | Error handling, retries, logging | Deploy with confidence |

## Available Analysis Types

```python
# 1. Threat Analysis
threat_result = await engine.analyze_threat(...)

# 2. Remediation Prioritization  
remediation_plan = await engine.prioritize_remediation(...)

# 3. Attack Path Analysis
attack_paths = await engine.analyze_attack_path(...)

# 4. Executive Summary
summary = await engine.generate_executive_summary(...)

# 5. MITRE ATT&CK Context
mitre_info = await engine.get_mitre_context(...)
```

## Configuration Options

### Environment Variables

```bash
# Provider Selection (choose one)
LLM_PROVIDER=openai        # or 'anthropic'

# OpenAI Configuration
OPENAI_API_KEY=sk-...
OPENAI_MODEL=gpt-4-turbo-preview
OPENAI_MAX_TOKENS=4096
OPENAI_TEMPERATURE=0.3

# Anthropic Configuration  
ANTHROPIC_API_KEY=sk-ant-...
ANTHROPIC_MODEL=claude-3-opus-20240229

# Caching (optional - auto-disables if Redis unavailable)
REDIS_URL=redis://localhost:6379
REDIS_CACHE_TTL=3600
```

## Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=shadowhawk --cov-report=html

# Run specific test
pytest tests/integration/test_ai_integration.py -v
```

## Common Tasks

### Check Stats
```python
stats = engine.get_stats()
print(f"Requests: {stats['llm']['requests']}")
print(f"Total Cost: ${stats['llm']['total_cost']:.4f}")
print(f"Cache Hit Rate: {stats['cache']['hit_rate_percent']:.1f}%")
```

### Clear Cache
```python
engine.cache.clear()
```

### Switch LLM Provider
```python
from shadowhawk.infrastructure.ai.llm_client import LLMClient, LLMProvider

# Use Anthropic instead
llm = LLMClient(provider=LLMProvider.ANTHROPIC)
engine = AIAnalysisEngine(llm_client=llm)
```

### Custom Prompts
```python
from shadowhawk.infrastructure.ai.prompt_library import PromptLibrary

prompts = PromptLibrary()
template = prompts.get("threat_explanation")
system, user = template.render(
    threat_id="CVE-2024-1234",
    threat_type="SQL Injection",
    # ... other variables
)
```

## Cost Estimates

| Model | Per Analysis | Per 100 | Per 1000 |
|-------|--------------|---------|----------|
| GPT-4 Turbo | $0.05-0.15 | $5-15 | $50-150 |
| Claude 3 Opus | $0.10-0.25 | $10-25 | $100-250 |
| Claude 3 Sonnet | $0.02-0.05 | $2-5 | $20-50 |

*With 70% cache hit rate, reduce costs by ~70%*

## Troubleshooting

### "No module named 'yaml'"
```bash
pip install pyyaml
```

### "Redis connection failed"
No problem! Caching auto-disables. To enable:
```bash
# Install Redis
docker run -d -p 6379:6379 redis
# OR
brew install redis && brew services start redis
```

### "API key not found"
```bash
# Check .env file exists and has your key
cat .env | grep API_KEY

# Verify environment variable is loaded
python -c "import os; print(os.getenv('OPENAI_API_KEY'))"
```

## Project Structure

```
shadowhawk/
├── src/shadowhawk/              # Main source code
│   ├── infrastructure/ai/       # LLM client, cache, prompts
│   └── application/engines/     # Analysis engine
├── config/prompts/              # YAML prompt templates
├── tests/                       # Test suite
│   ├── unit/                    # Unit tests
│   └── integration/             # Integration tests
├── examples/                    # Usage examples
└── [documentation files]
```

## Next Steps

1. **Read the docs**: Check out `SETUP.md` for detailed setup
2. **Review architecture**: See `ARCHITECTURE.md` for design details
3. **Run examples**: Try `examples/basic_usage.py`
4. **Write prompts**: Add custom templates in `config/prompts/`
5. **Integrate**: Use in your security pipeline

## Support & Resources

- 📖 **Full Documentation**: See `SETUP.md` and `ARCHITECTURE.md`
- 🧪 **Tests**: All test files in `tests/` directory
- 💡 **Examples**: Working code in `examples/` directory
- 🛠️ **Contributing**: Guidelines in `CONTRIBUTING.md`

## Quick Commands

```bash
make help          # Show all available commands
make install       # Install dependencies
make test          # Run tests
make format        # Format code
make run-example   # Run basic usage example
```

---

**Ready to analyze threats with AI?** Just set your API key and run `python examples/basic_usage.py`!
