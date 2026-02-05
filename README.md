# ShadowHawk Platform

Advanced Security Analysis Platform with AI-powered threat detection and remediation.

## Features

- **Real LLM Integration**: Uses OpenAI GPT-4 and Anthropic Claude for advanced analysis
- **Prompt Library System**: Version-controlled prompt templates for consistent AI outputs
- **Response Caching**: Redis-based caching to reduce API costs and improve performance
- **Cost Tracking**: Comprehensive tracking of LLM API usage and costs
- **Structured Outputs**: Validated and parsed AI responses using Pydantic models

## Installation

```bash
poetry install
```

## Configuration

Create a `.env` file with your API keys:

```
OPENAI_API_KEY=your_openai_key_here
ANTHROPIC_API_KEY=your_anthropic_key_here
REDIS_URL=redis://localhost:6379
```

## Usage

```python
from shadowhawk.application.engines.ai_analysis import AIAnalysisEngine

engine = AIAnalysisEngine()
result = await engine.analyze_threat(threat_data)
```

## Testing

```bash
poetry run pytest
```

## License

MIT License - see LICENSE file for details.
