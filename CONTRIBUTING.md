# Contributing to ShadowHawk Platform

Thank you for your interest in contributing to the ShadowHawk Platform!

## Development Setup

1. **Fork and clone the repository**

```bash
git clone https://github.com/your-username/shadowhawk.git
cd shadowhawk
```

2. **Install dependencies**

```bash
make install
# or
poetry install
```

3. **Set up pre-commit hooks** (optional but recommended)

```bash
poetry run pre-commit install
```

## Code Standards

### Python Style

- Follow PEP 8
- Use type hints for all function signatures
- Maximum line length: 100 characters
- Use Black for formatting: `make format`
- Use Ruff for linting: `make lint`

### Attribution Headers

All source files must include the copyright header:

```python
"""
File Description
Copyright (c) 2024 ShadowHawk Team
Licensed under the MIT License
"""
```

### Documentation

- All public functions must have docstrings
- Use Google-style docstrings
- Include type information in docstrings
- Provide usage examples for complex functions

Example:

```python
def analyze_threat(
    self,
    threat_id: str,
    severity: str,
) -> ThreatAnalysis:
    """
    Analyze security threat using LLM
    
    Args:
        threat_id: Unique threat identifier
        severity: Severity level (Critical, High, Medium, Low)
        
    Returns:
        Structured threat analysis with recommendations
        
    Raises:
        ValueError: If threat_id is empty
        
    Example:
        >>> engine = AIAnalysisEngine()
        >>> result = await engine.analyze_threat("CVE-2024-1234", "Critical")
        >>> print(result.executive_summary)
    """
```

## Testing

### Writing Tests

- Write tests for all new functionality
- Maintain or improve code coverage
- Use descriptive test names: `test_<function>_<scenario>`
- Use fixtures for common setup

### Test Structure

```python
def test_function_name_success_case() -> None:
    """Test successful execution of function_name"""
    # Arrange
    input_data = create_test_data()
    
    # Act
    result = function_name(input_data)
    
    # Assert
    assert result.status == "success"
```

### Running Tests

```bash
# All tests
make test

# With coverage
make test-cov

# Specific test file
poetry run pytest tests/unit/test_prompt_library.py -v

# Specific test
poetry run pytest tests/unit/test_prompt_library.py::test_prompt_template_render -v
```

## Adding New Prompts

1. Create a YAML file in `config/prompts/`:

```yaml
name: your_prompt_name
version: 1.0.0
description: Brief description of the prompt's purpose

system_prompt: |
  You are an expert in...
  Your role is to...

user_prompt: |
  Analyze the following:
  
  Input: ${variable_name}
  
  Provide your analysis in the following format:
  1. SECTION ONE
  2. SECTION TWO

tags:
  - category1
  - category2

examples:
  - input:
      variable_name: "example value"
    output: "expected output format"
```

2. Add a method to `AIAnalysisEngine` class:

```python
async def your_new_analysis(
    self,
    input_param: str,
) -> YourOutputModel:
    """Your method description"""
    template = self.prompts.get("your_prompt_name")
    system_prompt, user_prompt = template.render(
        variable_name=input_param,
    )
    
    response = await self._complete_with_cache(user_prompt, system_prompt)
    return self._parse_your_response(response["content"])
```

3. Add tests in `tests/integration/test_ai_integration.py`

4. Update documentation

## Pull Request Process

1. **Create a feature branch**

```bash
git checkout -b feature/your-feature-name
```

2. **Make your changes**

- Write code following style guidelines
- Add tests
- Update documentation

3. **Run quality checks**

```bash
make format
make lint
make type-check
make test
```

4. **Commit your changes**

```bash
git add .
git commit -m "Add feature: description of your changes"
```

Use conventional commit messages:
- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation changes
- `test:` - Test additions/changes
- `refactor:` - Code refactoring
- `chore:` - Maintenance tasks

5. **Push and create PR**

```bash
git push origin feature/your-feature-name
```

Then create a pull request on GitHub.

### PR Checklist

- [ ] Code follows style guidelines
- [ ] All tests pass
- [ ] New tests added for new functionality
- [ ] Documentation updated
- [ ] Attribution headers added to new files
- [ ] No sensitive data (API keys, passwords) in code
- [ ] Commit messages are clear and descriptive

## Project Structure

```
shadowhawk/
├── src/shadowhawk/           # Main source code
│   ├── application/          # Application layer (business logic)
│   │   └── engines/          # Analysis engines
│   └── infrastructure/       # Infrastructure layer (external services)
│       └── ai/               # AI infrastructure
├── config/                   # Configuration files
│   └── prompts/              # Prompt templates
├── tests/                    # Test suite
│   ├── integration/          # Integration tests
│   └── unit/                 # Unit tests
├── examples/                 # Usage examples
└── docs/                     # Additional documentation
```

## Architecture Principles

### Layered Architecture

- **Application Layer**: Business logic and use cases
- **Infrastructure Layer**: External service integrations
- **Clear separation**: No infrastructure code in application layer

### Dependency Injection

Use dependency injection for testability:

```python
class AIAnalysisEngine:
    def __init__(
        self,
        llm_client: Optional[LLMClient] = None,
        prompt_library: Optional[PromptLibrary] = None,
    ):
        self.llm = llm_client or LLMClient()
        self.prompts = prompt_library or PromptLibrary()
```

### Error Handling

- Use specific exception types
- Log errors with context
- Fail gracefully when possible
- Provide meaningful error messages

### Security

- Never log sensitive data
- Sanitize user inputs
- Use environment variables for secrets
- Implement rate limiting where appropriate

## Questions?

- Open an issue for bugs or feature requests
- Start a discussion for questions or ideas
- Check existing issues and PRs first

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
