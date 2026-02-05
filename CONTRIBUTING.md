# Contributing to ShadowHawk Platform

 cto-task-goaldesign-and-implement-the-initial-architecture-and-core-m
Thank you for considering contributing to the ShadowHawk Platform! This document provides guidelines and instructions for contributing.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Coding Standards](#coding-standards)
- [Commit Guidelines](#commit-guidelines)
- [Pull Request Process](#pull-request-process)
- [Testing Requirements](#testing-requirements)
- [Attribution Requirements](#attribution-requirements)

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Prioritize security and quality
- Document your changes thoroughly

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone <your-fork-url>`
3. Create a feature branch: `git checkout -b feature/your-feature-name`
4. Make your changes
5. Test thoroughly
6. Submit a pull request

## Development Setup

1. Install Python 3.11+
2. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate
   ```

3. Install development dependencies:
   ```bash
   pip install -r requirements.txt
   pip install -r requirements-dev.txt
   ```

4. Install pre-commit hooks:
   ```bash
   pre-commit install
   ```

5. Set up local configuration:
   ```bash
   cp .env.example .env
   ```

## Coding Standards

### Python Style Guide

We follow PEP 8 with these additions:

- **Line Length**: Maximum 100 characters
- **Imports**: Organized using `isort`
- **Formatting**: Use `black` for code formatting
- **Type Hints**: Required for all function signatures
- **Docstrings**: Google-style docstrings for all public functions/classes

Example:

```python
"""
ShadowHawk Platform - Threat Detection Module

Copyright (c) 2024 ShadowHawk Platform
Licensed under the MIT License
See LICENSE file in the project root for full license information.
"""

from typing import List, Optional
from datetime import datetime


def analyze_threat(
    indicators: List[str],
    context: Optional[dict] = None
) -> dict:
    """
    Analyze threat indicators and return assessment.

    Args:
        indicators: List of threat indicators to analyze
        context: Optional context information for analysis

    Returns:
        Dictionary containing threat analysis results

    Raises:
        ValueError: If indicators list is empty
    """
    if not indicators:
        raise ValueError("Indicators list cannot be empty")
    
    # Implementation here
    return {}
```

### Architecture Principles

1. **Clean Architecture**: Maintain strict layer separation
   - Domain layer: No dependencies on outer layers
   - Application layer: Depends only on domain
   - Infrastructure: Implements domain interfaces
   - API layer: Thin, delegates to application layer

2. **Dependency Injection**: Use constructor injection for dependencies

3. **SOLID Principles**: Follow SOLID design principles

4. **Immutability**: Prefer immutable data structures where possible

### Security Guidelines

- **Input Validation**: Validate all inputs at API boundaries
- **Output Encoding**: Encode all outputs appropriately
- **Authentication**: Never bypass authentication checks
- **Authorization**: Check permissions before all operations
- **Secrets**: Never commit secrets or API keys
- **Logging**: Log security events, but not sensitive data

## Commit Guidelines

### Commit Message Format

```
<type>(<scope>): <subject>

<body>

<footer>
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

**Examples:**

```
feat(threat-modeling): add STRIDE classification support

Implement STRIDE-based threat classification for asset modeling.
Includes support for Spoofing, Tampering, Repudiation, Information
Disclosure, Denial of Service, and Elevation of Privilege categories.

Closes #123
```

```
fix(auth): resolve token expiration validation

Fix issue where expired tokens were not properly rejected due to
timezone handling error.

Fixes #456
```

## Pull Request Process

1. **Update Documentation**: Update README.md and docs/ if needed
2. **Add Tests**: Include unit and integration tests
3. **Run Tests**: Ensure all tests pass
4. **Code Quality**: Run linters and formatters
5. **Attribution**: Ensure all new files have attribution headers
6. **Changelog**: Update CHANGELOG.md if applicable

### PR Title Format

```
[Type] Brief description of changes
```

Example: `[Feature] Add MITRE ATT&CK mapping engine`

### PR Description Template

```markdown
## Description
Brief description of the changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] Manual testing completed

## Checklist
- [ ] Code follows project style guidelines
- [ ] Self-review completed
- [ ] Comments added for complex logic
- [ ] Documentation updated
- [ ] No new warnings generated
- [ ] Tests pass locally
- [ ] Attribution headers added to new files

## Related Issues
Closes #(issue number)
```

## Testing Requirements

### Unit Tests

- **Coverage**: Minimum 80% code coverage
- **Isolation**: Tests should be independent
- **Naming**: `test_<function_name>_<scenario>`
- **Arrange-Act-Assert**: Follow AAA pattern

Example:

```python
def test_risk_score_calculation_with_high_severity():
    # Arrange
    vulnerability = Vulnerability(severity="high", cvss_score=8.5)
    engine = RiskScoringEngine()
    
    # Act
    result = engine.calculate_risk(vulnerability)
    
    # Assert
    assert result.score >= 7.0
    assert result.level == "high"
```

### Integration Tests

- Test complete workflows
- Use test databases/fixtures
- Clean up after tests
- Test error scenarios

### Security Tests

- Test authentication mechanisms
- Verify RBAC enforcement
- Test input validation
- Verify audit logging

## Attribution Requirements

### File Headers

All source code files MUST include this attribution header:

```python
"""
ShadowHawk Platform - <Module Name>

Copyright (c) 2024 ShadowHawk Platform
Licensed under the MIT License
See LICENSE file in the project root for full license information.

Author: <Your Name> <your.email@example.com>
Created: <YYYY-MM-DD>
"""
```

### Configuration Files

Configuration files (YAML, JSON, etc.) should include:

```yaml
# ShadowHawk Platform - Configuration
# Copyright (c) 2024 ShadowHawk Platform
# Licensed under the MIT License
```

### Documentation Files

Markdown files should include:

```markdown
<!-- 
ShadowHawk Platform Documentation
Copyright (c) 2024 ShadowHawk Platform
Licensed under the MIT License
-->
```

## Development Workflow

### 1. Create Feature Branch

```bash
git checkout -b feature/my-new-feature
```

### 2. Make Changes

- Follow coding standards
- Add attribution headers
- Write tests
- Update documentation

### 3. Run Quality Checks

```bash
# Format code
black src/ tests/

# Sort imports
isort src/ tests/

# Lint code
flake8 src/ tests/
pylint src/

# Type checking
mypy src/

# Run tests
pytest --cov=src/shadowhawk
```

### 4. Commit Changes

```bash
git add .
git commit -m "feat(engine): add new detection rule type"
```

### 5. Push and Create PR

```bash
git push origin feature/my-new-feature
```

Then create a pull request on GitHub.

## Review Process

1. **Automated Checks**: CI/CD pipeline runs automatically
2. **Code Review**: At least one maintainer review required
3. **Testing**: All tests must pass
4. **Documentation**: Documentation must be updated
5. **Security**: Security review for sensitive changes

## Questions?

If you have questions:

1. Check existing documentation
2. Search existing issues
3. Open a new issue with the `question` label

## License

By contributing to ShadowHawk Platform, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to ShadowHawk Platform! 🛡️

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
 main
