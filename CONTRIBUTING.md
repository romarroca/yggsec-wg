# Contributing to YggSec WireG

Thank you for your interest in contributing to YggSec WireG! This document provides guidelines for contributing to the project.

## Table of Contents
- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Environment](#development-environment)
- [Contributing Process](#contributing-process)
- [Security Guidelines](#security-guidelines)
- [Testing](#testing)
- [Documentation](#documentation)

## Code of Conduct

This project adheres to a code of conduct that we expect all contributors to follow:
- Be respectful and inclusive
- Focus on constructive feedback
- Be patient with new contributors
- Prioritize security and user safety

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/your-username/yggsec-wireG.git
   cd yggsec-wireG
   ```
3. **Create a feature branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

## Development Environment

### Prerequisites
- Ubuntu 20.04+ or Debian 11+
- Python 3.8+
- WireGuard tools
- nftables
- Root access for testing

### Local Development Setup
```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install development tools
pip install flake8 black isort mypy bandit safety
```

### Architecture Guidelines

Follow the established patterns in the codebase:

- **Separation of Concerns**: Keep `api/`, `core/`, `services/` layers distinct
- **Security First**: All user inputs must be validated
- **Error Handling**: Use centralized error handling (`src/utils/error_handler.py`)
- **Documentation**: Add docstrings to all functions

## Contributing Process

### 1. Issue Creation
- **Bug Reports**: Use the bug report template
- **Feature Requests**: Use the feature request template
- **Security Issues**: Use private disclosure for vulnerabilities

### 2. Development
- Write clean, documented code
- Follow existing code style and patterns
- Add tests for new functionality
- Ensure security considerations are addressed

### 3. Testing
```bash
# Run security checks
bandit -r src/
safety check --requirements requirements.txt

# Run code quality checks
black --check src/
flake8 src/
isort --check src/
```

### 4. Pull Request
- Fill out the pull request template completely
- Ensure all checks pass
- Request review from maintainers
- Address feedback promptly

## Security Guidelines

### Security-First Development
- **Input Validation**: Validate all user inputs using `src/core/validators.py`
- **Command Injection**: Never use shell=True with subprocess
- **Path Traversal**: Sanitize all file paths
- **Secrets**: Never commit secrets or keys
- **Privileges**: Follow principle of least privilege

### Security Review Process
All security-related changes require:
1. Security impact assessment
2. Code review by maintainers
3. Testing in isolated environment
4. Documentation of security implications

### Vulnerability Disclosure
- **Private First**: Report vulnerabilities privately
- **Coordinated Disclosure**: Work with maintainers on fixes
- **Credit**: Security researchers will be credited

## Testing

### Test Types
- **Unit Tests**: Test individual functions
- **Integration Tests**: Test component interactions
- **Security Tests**: Test for common vulnerabilities
- **System Tests**: Test on actual Ubuntu/Debian systems

### Testing Infrastructure
```bash
# Run existing tests
python -m pytest tests/

# Manual testing
sudo ./scripts/init.sh /tmp/test-install
```

### Test Coverage
- Aim for >80% code coverage
- Prioritize security-critical paths
- Include edge case testing

## Documentation

### Documentation Types
- **Code Comments**: Inline documentation for complex logic
- **Docstrings**: Function and class documentation
- **README Updates**: Keep installation guide current
- **Architecture Docs**: Document design decisions

### Documentation Standards
- Use clear, concise language
- Include examples where helpful
- Update when code changes
- Consider non-native English speakers

## Coding Standards

### Python Style
- Follow PEP 8
- Use Black for formatting
- Use isort for import sorting
- Maximum line length: 127 characters

### Security Standards
- Validate all inputs
- Sanitize all outputs
- Use parameterized queries
- Follow OWASP guidelines

### Git Commit Messages
```
type: brief description

Longer description if needed

- Specific changes made
- Why changes were necessary
- Any breaking changes

Closes #123
```

## Release Process

### Version Management
- Use semantic versioning (MAJOR.MINOR.PATCH)
- Tag releases with security notes
- Maintain changelog

### Security Releases
- Coordinate with security researchers
- Provide clear upgrade instructions
- Document security impact

## Getting Help

- **Issues**: Create a GitHub issue for bugs/features
- **Discussions**: Use GitHub Discussions for questions
- **Security**: Use private disclosure for security issues

## Recognition

Contributors will be recognized in:
- GitHub contributors list
- Release notes
- Security hall of fame (for security researchers)

Thank you for contributing to YggSec WireG! 🚀