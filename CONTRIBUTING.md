# Contributing to ShadowHawk Platform

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
