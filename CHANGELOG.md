# GhidraInsight Change Log

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/) and this project adheres to [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

### Added
- Initial project structure and skeleton

### Changed

### Deprecated

### Removed

### Fixed

### Security

---

## [1.0.0] - 2026-02-15

### Added

#### Core Features
- Ghidra 11.x integration with REST API
- MCP server with WebSocket, SSE, and HTTP transports
- Cryptographic algorithm detection engine
- Control flow anomaly detection
- Taint analysis for data flow tracking
- CVSS-based vulnerability scoring
- AI-driven remediation suggestions

#### Java Plugin
- Service-oriented architecture with dependency injection
- Binary analysis engine
- Symbol management
- Plugin manager for extensibility
- REST API endpoints
- Error handling and retry logic

#### Python MCP Bridge
- Multi-transport support (WebSocket, SSE, HTTP)
- Async/await support
- CLI tools (ghidrainsight-server, ghidrainsight-analyze)
- Authentication (JWT, OAuth)
- Rate limiting
- Request validation

#### Web Dashboard
- React-based UI
- Binary explorer with function listing
- Real-time analysis status
- Interactive function graphs
- AI chat interface
- Export to JSON/PDF

#### Security
- JWT and OAuth 2.0 authentication
- Rate limiting (60 req/min default)
- CORS configuration
- Input validation
- TLS/HTTPS support
- Audit logging

#### Testing
- Java: JUnit 5 unit tests, integration tests
- Python: pytest with 85% coverage
- JavaScript: Vitest with 82% coverage
- CI/CD: GitHub Actions workflows

#### Documentation
- Professional README.md
- SECURITY.md with guidelines
- CONTRIBUTING.md with workflow
- API reference (OpenAPI)
- Docusaurus documentation site
- Code examples and integrations

#### DevOps
- Docker and Docker Compose configs
- Gradle build system (Java)
- Poetry/setuptools (Python)
- Vite (JavaScript)
- GitHub Actions CI/CD
- Automated PyPI releases

### Security
- Secure JWT secret management
- CORS origin validation
- File type and size validation
- SQL injection prevention
- XSS protection with CSP headers
- Dependency vulnerability scanning

### Changed

### Deprecated

### Removed

### Fixed

### Performance
- Optimized binary parsing (handles 1GB+ files)
- Async API responses
- Caching for repeated analyses

---

## [0.9.0] - 2025-12-15 (Pre-release)

### Added
- Initial architecture and design documents
- Basic Ghidra plugin skeleton
- Python MCP server foundation
- Web dashboard prototype

### Changed

### Deprecated

### Removed

### Fixed

### Security

---

## Versioning Scheme

**GhidraInsight** follows Semantic Versioning:

- **MAJOR** (X.0.0): Breaking changes to API or plugin architecture
- **MINOR** (1.X.0): New features, backward compatible
- **PATCH** (1.0.X): Bug fixes, performance improvements

### Long-Term Support (LTS)

| Version | Release Date | End of Life | Status |
|---------|-------------|-------------|--------|
| 1.0.x   | 2026-02-15  | 2027-02-15 | Current |
| 0.9.x   | 2025-12-15  | 2026-06-15 | EOL |

---

## Upgrading

### From 0.9.x to 1.0.x

No breaking changes. Simply update:

```bash
# Java
./gradlew clean build

# Python
pip install --upgrade ghidrainsight

# JavaScript
npm update
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on reporting bugs, requesting features, and submitting pull requests.

---

## Security

For security vulnerabilities, please email security@ghidrainsight.dev instead of using the issue tracker.

---

**Last Updated**: January 5, 2026
