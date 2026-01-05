# Contributing to GhidraInsight

Thank you for your interest in contributing to GhidraInsight! We appreciate your help in making this project better.

---

## 📋 Code of Conduct

Please be respectful and constructive in all interactions. We follow the [Contributor Covenant](https://www.contributor-covenant.org/).

---

## 🚀 Getting Started

### 1. Fork & Clone

```bash
git clone https://github.com/yourusername/GhidraInsight.git
cd GhidraInsight
```

### 2. Set Up Development Environment

#### Java/Gradle Setup
```bash
cd ghidra-plugin
./gradlew build
```

#### Python Setup
```bash
cd python-mcp
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -e ".[dev]"
```

#### Node.js Setup
```bash
cd web-dashboard
npm install
npm run dev
```

### 3. Run Tests

```bash
# Java
./gradlew test

# Python
pytest tests/

# JavaScript
npm test
```

---

## 💻 Development Workflow

### 1. Create a Feature Branch

```bash
git checkout -b feature/your-feature-name
```

Use descriptive names:
- `feature/crypto-detection` ✅
- `fix/null-pointer-exception` ✅
- `docs/api-reference` ✅
- `test/add-unit-tests` ✅

### 2. Code Guidelines

#### Java

- **Style**: Google Java Style Guide
- **Formatting**: `./gradlew spotlessApply`
- **Naming**: camelCase for variables/methods, PascalCase for classes
- **Documentation**: JavaDoc for public methods

```java
/**
 * Detects cryptographic algorithms in a binary.
 *
 * @param binary the binary file to analyze
 * @return a set of detected algorithms
 * @throws IOException if the file cannot be read
 */
public Set<CryptoAlgorithm> detectCrypto(File binary) throws IOException {
    // Implementation
}
```

#### Python

- **Style**: PEP 8 (enforced by Black)
- **Formatting**: `black ghidrainsight/`
- **Linting**: `flake8 ghidrainsight/`
- **Type Hints**: Required for all functions

```python
from typing import Set

def detect_crypto(binary_path: str) -> Set[str]:
    """
    Detect cryptographic algorithms in a binary.
    
    Args:
        binary_path: Path to the binary file
        
    Returns:
        Set of detected algorithm names
        
    Raises:
        FileNotFoundError: If the file doesn't exist
        IOError: If the file cannot be read
    """
    pass
```

#### TypeScript/React

- **Style**: Airbnb ESLint config
- **Formatting**: `prettier --write src/`
- **Linting**: `eslint src/`
- **Components**: Functional components with hooks

```typescript
interface AnalysisResult {
  functionCount: number;
  vulnerabilities: Vulnerability[];
}

export const AnalysisViewer: React.FC<{ result: AnalysisResult }> = ({ result }) => {
  return <div>{/* Component code */}</div>;
};
```

### 3. Testing Requirements

**All contributions must include tests.**

#### Java (JUnit 5)
```java
@DisplayName("Crypto Detection Tests")
class CryptoDetectorTest {
    
    private CryptoDetector detector;
    
    @BeforeEach
    void setUp() {
        detector = new CryptoDetector();
    }
    
    @Test
    void shouldDetectAES() throws IOException {
        // Test implementation
    }
}
```

#### Python (pytest)
```python
def test_detect_crypto():
    detector = CryptoDetector()
    result = detector.detect(BINARY_PATH)
    assert "AES" in result
    assert len(result) > 0
```

#### TypeScript (Vitest)
```typescript
describe("AnalysisViewer", () => {
  it("should display function count", () => {
    const result = { functionCount: 42, vulnerabilities: [] };
    const { getByText } = render(<AnalysisViewer result={result} />);
    expect(getByText(/42/)).toBeTruthy();
  });
});
```

### 4. Commit Messages

Use conventional commit format:

```
<type>(<scope>): <subject>

<body>

<footer>
```

#### Types
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `style`: Code style (formatting, missing semicolons)
- `refactor`: Code refactoring
- `perf`: Performance improvement
- `test`: Adding tests
- `chore`: Build, dependencies, CI/CD

#### Examples

```
feat(crypto): add AES-256 detection algorithm

Implement detection for AES-256 using pattern matching on key schedules.
Adds 50 new test cases.

Closes #123
```

```
fix(taint): resolve null pointer in data flow analysis

The taint analyzer was throwing NPE when encountering indirect jumps.
Added null check and proper handling for unknown targets.

Fixes #456
```

---

## 🔄 Pull Request Process

### 1. Submit PR

Push your branch and open a PR on GitHub:

```bash
git push origin feature/your-feature-name
```

### 2. PR Template (Fill This Out)

```markdown
## Description
Brief description of what this PR does.

## Related Issues
Closes #123

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation

## Testing
- [ ] Added unit tests
- [ ] Added integration tests
- [ ] All tests pass locally

## Checklist
- [ ] Code follows style guidelines
- [ ] Documentation updated
- [ ] No new warnings generated
- [ ] Tests added/updated
- [ ] CHANGELOG.md updated
```

### 3. Review Process

- **Automated Checks**:
  - ✅ All tests pass
  - ✅ Code coverage maintained (80%+)
  - ✅ Linting passed
  - ✅ No security issues

- **Manual Review**:
  - ✅ Code quality
  - ✅ Architecture alignment
  - ✅ Documentation clarity

- **Approval**: Requires 2 approvals for merge

---

## 🧪 Testing Standards

### Coverage Requirements

- **Overall**: 80%+ code coverage
- **Critical paths**: 95%+
- **Utils**: 100%

### Run Coverage Report

```bash
# Java
./gradlew test jacocoTestReport
# Open: build/reports/jacoco/test/html/index.html

# Python
pytest --cov=ghidrainsight --cov-report=html
# Open: htmlcov/index.html

# Node.js
npm test -- --coverage
# Open: coverage/index.html
```

---

## 📚 Documentation

### When to Update Docs

- ✅ New features → Add to README + API docs
- ✅ API changes → Update OpenAPI spec
- ✅ New CLI commands → Update CLI help
- ✅ Security changes → Update SECURITY.md
- ✅ Breaking changes → Update CHANGELOG.md

### Documentation Files

- `README.md` - Project overview
- `SECURITY.md` - Security policies
- `CONTRIBUTING.md` - This file
- `CHANGELOG.md` - Version history
- `docs/` - Full documentation (Docusaurus)
- `docs/API_REFERENCE.md` - API reference
- `examples/` - Code examples

---

## 🔍 Code Review Checklist

Before requesting review, ensure:

- [ ] Code compiles/lints without warnings
- [ ] All tests pass locally
- [ ] 80%+ code coverage maintained
- [ ] Follows code style guidelines
- [ ] Commits are logically organized
- [ ] Commit messages are clear
- [ ] Documentation is updated
- [ ] No hardcoded secrets/keys
- [ ] No unnecessary dependencies added

---

## 📦 Adding Dependencies

### Java

```bash
# In ghidra-plugin/build.gradle.kts
dependencies {
    implementation("org.example:library:1.0.0")
    testImplementation("junit:junit:4.13")
}
```

### Python

```bash
# In python-mcp/pyproject.toml
dependencies = [
    "requests>=2.28.0",
    "aiohttp>=3.8.0",
]
```

### Node.js

```bash
npm install package-name
npm install --save-dev dev-package-name
```

**Note**: All new dependencies must be:
- ✅ Security audited (no known vulnerabilities)
- ✅ Approved by maintainers
- ✅ Added with version constraints

---

## 🚀 Performance Considerations

### Before Optimizing
- Measure performance impact
- Add benchmarks
- Document trade-offs

### Areas of Focus
- Binary analysis speed (handle 1GB+ files)
- API response time (<500ms target)
- Memory usage during analysis
- Dashboard UI responsiveness

---

## 🐛 Reporting Bugs

Use the GitHub Issue template:

```markdown
## Bug Description
Clear description of the bug.

## Steps to Reproduce
1. ...
2. ...

## Expected Behavior
What should happen.

## Actual Behavior
What actually happens.

## Environment
- OS: macOS 13.0
- Java: 11.0.13
- Ghidra: 11.0
```

---

## 📝 Feature Requests

Use the GitHub Issue template:

```markdown
## Feature Description
Clear description of the feature.

## Use Case
Why this feature is needed.

## Proposed Solution
How you think it should work.

## Alternatives Considered
Other approaches you considered.
```

---

## 🎓 Learning Resources

- [Ghidra API Docs](https://ghidra.re/api/)
- [MCP Specification](https://modelcontextprotocol.io/)
- [Google Java Style Guide](https://google.github.io/styleguide/javaguide.html)
- [PEP 8 Style Guide](https://pep8.org/)
- [React Best Practices](https://react.dev/)

---

## 🏆 Recognition

Contributors are recognized in:
- `CONTRIBUTORS.md`
- Release notes
- GitHub contributors page

---

## ❓ Questions?

- **Discussions**: [GitHub Discussions](https://github.com/yourusername/GhidraInsight/discussions)
- **Issues**: [GitHub Issues](https://github.com/yourusername/GhidraInsight/issues)
- **Email**: support@ghidrainsight.dev

---

## Thank You! 🙏

Your contributions make GhidraInsight better for everyone. We appreciate your time and effort!

---

**Happy coding! 🚀**
