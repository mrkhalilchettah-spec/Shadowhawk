# ShadowHawk Platform Architecture

## Overview

The ShadowHawk Platform is a production-ready AI-powered security analysis system that replaces placeholder AI functionality with real LLM integration. The architecture follows clean architecture principles with clear separation between business logic and infrastructure.

## System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Application Layer                        │
│  ┌─────────────────────────────────────────────────────┐   │
│  │         AI Analysis Engine                          │   │
│  │  - analyze_threat()                                 │   │
│  │  - prioritize_remediation()                         │   │
│  │  - analyze_attack_path()                            │   │
│  │  - generate_executive_summary()                     │   │
│  │  - get_mitre_context()                              │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                   Infrastructure Layer                       │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │ LLM Client   │  │ Prompt       │  │ Response     │     │
│  │              │  │ Library      │  │ Cache        │     │
│  │ - OpenAI     │  │              │  │              │     │
│  │ - Anthropic  │  │ - Templates  │  │ - Redis      │     │
│  │ - Cost Track │  │ - Versioning │  │ - TTL        │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                    External Services                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │ OpenAI API   │  │ Anthropic API│  │ Redis        │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
└─────────────────────────────────────────────────────────────┘
```

## Components

### 1. AI Analysis Engine (`ai_analysis.py`)

**Purpose**: High-level business logic for security analysis using AI.

**Responsibilities**:
- Orchestrate LLM requests for various analysis types
- Parse and structure LLM responses
- Manage caching and cost tracking
- Provide consistent interface for security analysis

**Key Methods**:
- `analyze_threat()`: Analyze security threats with detailed breakdowns
- `prioritize_remediation()`: Prioritize security findings for remediation
- `analyze_attack_path()`: Model potential attack paths and kill chains
- `generate_executive_summary()`: Create executive-friendly summaries
- `get_mitre_context()`: Map findings to MITRE ATT&CK framework

**Design Patterns**:
- Dependency Injection: Accepts optional dependencies for testing
- Strategy Pattern: Supports multiple LLM providers
- Facade Pattern: Simplifies complex LLM interactions

### 2. LLM Client (`llm_client.py`)

**Purpose**: Unified interface for multiple LLM providers.

**Responsibilities**:
- Abstract OpenAI and Anthropic APIs
- Handle authentication and configuration
- Track token usage and costs
- Implement retry logic with exponential backoff
- Calculate real-time costs based on token usage

**Features**:
- Multi-provider support (OpenAI, Anthropic)
- Automatic retry on failures
- Comprehensive usage statistics
- Real-time cost calculation
- Provider-specific optimizations

**Cost Tracking**:
```python
{
    "total_tokens": 450,
    "prompt_tokens": 150,
    "completion_tokens": 300,
    "total_cost": 0.0105,
    "requests": 1,
    "errors": 0,
}
```

### 3. Prompt Library (`prompt_library.py`)

**Purpose**: Manage versioned prompt templates.

**Responsibilities**:
- Load prompt templates from YAML files
- Provide template interpolation
- Support versioning and tagging
- Enable prompt reuse and consistency

**Template Structure**:
```yaml
name: template_name
version: 1.0.0
description: Template description
system_prompt: |
  System instructions...
user_prompt: |
  User prompt with ${variables}...
tags:
  - category1
  - category2
examples:
  - input: {...}
    output: "..."
```

**Benefits**:
- Version-controlled prompts
- Easy A/B testing
- Consistent outputs
- Reusable across analyses

### 4. Response Cache (`response_cache.py`)

**Purpose**: Cache LLM responses to reduce costs and latency.

**Responsibilities**:
- Cache responses based on request parameters
- Implement TTL-based expiration
- Track cache hit/miss rates
- Handle Redis connection failures gracefully

**Cache Key Generation**:
```python
key = hash(prompt + system_prompt + model + temperature + max_tokens)
```

**Statistics**:
```python
{
    "enabled": True,
    "hits": 80,
    "misses": 20,
    "total_requests": 100,
    "hit_rate_percent": 80.0,
}
```

## Data Flow

### Threat Analysis Flow

```
1. User Request
   └─> ai_engine.analyze_threat(threat_data)

2. Prompt Generation
   └─> prompt_library.get("threat_explanation")
   └─> template.render(**threat_data)

3. Cache Check
   └─> response_cache.get(prompt_hash)
   │
   ├─> Cache Hit: Return cached response
   │
   └─> Cache Miss:
       └─> llm_client.complete(prompt)
       └─> response_cache.set(prompt_hash, response)

4. Response Processing
   └─> Parse LLM response
   └─> Structure into ThreatAnalysis model
   └─> Update statistics

5. Return Result
   └─> ThreatAnalysis object with structured data
```

## Configuration Management

### Environment Variables

Configuration is managed through environment variables:

```env
# LLM Provider
LLM_PROVIDER=openai
OPENAI_API_KEY=sk-xxx
OPENAI_MODEL=gpt-4-turbo-preview
OPENAI_MAX_TOKENS=4096
OPENAI_TEMPERATURE=0.3

# Caching
REDIS_URL=redis://localhost:6379
REDIS_CACHE_TTL=3600

# Monitoring
ENABLE_COST_TRACKING=true
LOG_LEVEL=INFO
```

### Prompt Configuration

Prompts are configured in YAML files:

```
config/
└── prompts/
    ├── threat_explanation.yaml
    ├── remediation_prioritization.yaml
    ├── attack_path.yaml
    ├── executive_summary.yaml
    └── mitre_context.yaml
```

## Error Handling

### Retry Strategy

The LLM client implements exponential backoff:

```python
@retry(
    retry=retry_if_exception_type((Exception,)),
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=10),
)
```

### Graceful Degradation

- **Redis unavailable**: Disable caching, continue with direct LLM calls
- **LLM API error**: Retry with exponential backoff, then fail
- **Invalid prompt**: Raise descriptive error with missing variables

## Security Considerations

### API Key Management

- Store keys in environment variables
- Never commit keys to version control
- Use separate keys for dev/staging/prod
- Rotate keys regularly

### Input Validation

- Validate all user inputs before LLM requests
- Sanitize prompts to prevent injection
- Limit input sizes to prevent abuse

### Cost Controls

- Track spending in real-time
- Set budget alerts
- Implement rate limiting
- Use caching to reduce duplicate calls

## Performance Optimization

### Caching Strategy

- **TTL**: 1 hour default (configurable)
- **Key Generation**: Hash of all request parameters
- **Hit Rate**: Target 60-80% for typical usage
- **Storage**: Redis for distributed caching

### Cost Optimization

1. **Prompt Engineering**: Minimize token usage
2. **Response Caching**: Avoid duplicate requests
3. **Model Selection**: Use appropriate model for task
4. **Batch Processing**: Combine related analyses

### Expected Performance

- **Without Cache**: 2-5 seconds per analysis
- **With Cache Hit**: <100ms per analysis
- **Cost Per Analysis**: $0.02-0.15 (model dependent)
- **Cache Hit Rate**: 60-80% (typical usage)

## Extensibility

### Adding New Analysis Types

1. Create new prompt template in `config/prompts/`
2. Add output model in `ai_analysis.py`
3. Implement analysis method
4. Add parsing logic
5. Write tests

### Adding New LLM Providers

1. Add provider to `LLMProvider` enum
2. Implement provider-specific completion method
3. Add pricing information
4. Update configuration
5. Add tests

### Custom Response Parsing

Override parsing methods in `AIAnalysisEngine`:

```python
def _parse_custom_response(self, content: str) -> CustomModel:
    """Parse custom response format"""
    # Custom parsing logic
    return CustomModel(...)
```

## Testing Strategy

### Unit Tests

- Test individual components in isolation
- Mock external dependencies
- Focus on business logic
- Fast execution (<1s total)

### Integration Tests

- Test component interactions
- Use mock LLM responses
- Verify end-to-end flows
- Test error handling

### Test Coverage Goals

- Overall: >80%
- Business Logic: >90%
- Infrastructure: >70%

## Monitoring and Observability

### Logging

Structured logging with `structlog`:

```python
logger.info(
    "threat_analysis_complete",
    threat_id=threat_id,
    cost=response["cost"],
    tokens=response["total_tokens"],
)
```

### Metrics to Track

- **Usage**: Requests per hour/day
- **Cost**: Tokens and $ per analysis type
- **Performance**: Latency percentiles
- **Cache**: Hit rate, miss rate
- **Errors**: Error rate by type

## Future Enhancements

### Short Term

- [ ] Function calling for structured outputs
- [ ] Streaming responses for long analyses
- [ ] Async batch processing
- [ ] Prompt versioning with A/B testing

### Long Term

- [ ] Fine-tuned models for specific analysis types
- [ ] Multi-modal analysis (images, network diagrams)
- [ ] Real-time threat intelligence integration
- [ ] Automated prompt optimization

## References

- [OpenAI API Documentation](https://platform.openai.com/docs)
- [Anthropic API Documentation](https://docs.anthropic.com)
- [MITRE ATT&CK Framework](https://attack.mitre.org)
- [Clean Architecture Principles](https://blog.cleancoder.com/uncle-bob/2012/08/13/the-clean-architecture.html)
