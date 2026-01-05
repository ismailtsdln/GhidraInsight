# Security Policy for GhidraInsight

## 🔐 Security Overview

GhidraInsight is designed with security as a first-class concern. This document outlines our security practices, policies, and guidelines.

---

## 1. Reporting Security Vulnerabilities

**Please do NOT open public GitHub issues for security vulnerabilities.**

Instead, report security issues to: **security@ghidrainsight.dev**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if available)

We will:
- Acknowledge receipt within 48 hours
- Provide status updates every 7 days
- Release a patch within 30 days when critical
- Credit the reporter (unless anonymity is preferred)

---

## 2. Authentication & Authorization

### Supported Methods

#### JWT (JSON Web Tokens)
```yaml
auth:
  type: jwt
  secret: ${GHIDRA_JWT_SECRET}  # At least 32 characters
  algorithm: HS256
  expiration: 3600  # 1 hour
```

#### OAuth 2.0
```yaml
auth:
  type: oauth2
  provider: openid-connect
  client_id: ${OAUTH_CLIENT_ID}
  client_secret: ${OAUTH_CLIENT_SECRET}
  scopes: [openid, profile, email]
```

#### API Keys
```bash
X-API-Key: your-api-key-here
```

### Best Practices

1. **Never commit secrets** - Use environment variables
2. **Rotate credentials regularly** - At least quarterly
3. **Use strong secrets** - Minimum 32 characters, mixed case + numbers + symbols
4. **Token expiration** - Set short TTL (1-24 hours)
5. **Revocation** - Implement token blacklist for logout

---

## 3. Rate Limiting & DDoS Protection

### Default Configuration

```yaml
security:
  rate_limit:
    enabled: true
    requests_per_minute: 60
    burst_size: 10
    per_user: true
    
  ddos_protection:
    enabled: true
    captcha: false
    ip_blocking: true
```

### Custom Limits

```bash
ghidrainsight-server --rate-limit 120 --burst-size 20
```

---

## 4. Data Protection

### Encryption

- **In Transit**: TLS 1.2+ (enforced)
- **At Rest**: AES-256 for sensitive data
- **Database**: Encrypted fields for credentials

### Configuration

```yaml
encryption:
  enabled: true
  algorithm: AES-256-GCM
  key_rotation_days: 90
```

### Sensitive Data

The following data should be treated as sensitive:
- API keys and credentials
- JWT secrets
- OAuth tokens
- Binary file contents (if user marks as sensitive)
- Analysis results containing vulnerabilities

---

## 5. CORS & Access Control

### Default CORS Policy

```yaml
security:
  cors:
    enabled: true
    allowed_origins:
      - http://localhost:3000  # Development
    allowed_methods: [GET, POST, PUT, DELETE]
    allowed_headers: [Content-Type, Authorization]
    credentials: true
    max_age: 86400
```

### Production Setup

```yaml
security:
  cors:
    allowed_origins:
      - https://yourdomain.com
      - https://api.yourdomain.com
    credentials: true
```

---

## 6. Input Validation & Sanitization

### Implemented Protections

- ✅ File size limits (max 1GB binary)
- ✅ File type validation (ELF, PE, Mach-O, raw)
- ✅ Path traversal prevention
- ✅ SQL injection prevention (parameterized queries)
- ✅ XSS prevention (CSP headers)
- ✅ Request size limits (max 100MB)

### Example Validation

```java
public void validateBinaryFile(File file) {
    if (file.length() > 1_073_741_824L) {
        throw new ValidationException("File exceeds 1GB limit");
    }
    
    String magic = readFileMagic(file);
    if (!SUPPORTED_FORMATS.contains(magic)) {
        throw new ValidationException("Unsupported file format");
    }
}
```

---

## 7. Dependency Management

### Security Scanning

We use:
- **Java**: Dependabot + OWASP DependencyCheck
- **Python**: Safety + Bandit
- **Node.js**: npm audit + Snyk

### Update Policy

- **Critical**: Patch within 7 days
- **High**: Patch within 14 days
- **Medium**: Patch within 30 days
- **Low**: Patch in next release

---

## 8. Logging & Monitoring

### What We Log

```
✅ Authentication attempts (with failures)
✅ API requests (without binary contents)
✅ Errors and exceptions
✅ Configuration changes
❌ API keys/secrets (never)
❌ User passwords (never)
❌ Full binary contents (configurable)
```

### Log Retention

- **Development**: 7 days
- **Production**: 90 days
- **Compliance**: 1 year (if required)

### Example Log Entry

```json
{
  "timestamp": "2024-01-05T10:30:45Z",
  "level": "INFO",
  "service": "auth",
  "event": "login_success",
  "user_id": "user_123",
  "ip_address": "192.168.1.1",
  "session_id": "sess_abc123"
}
```

---

## 9. Secure Development Practices

### Code Review

- All PRs require 2 approvals
- Security review required for:
  - Authentication changes
  - Dependency updates
  - Database/API schema changes

### Static Analysis

Run before committing:

```bash
# Java
./gradlew spotbugsMain checkstyleMain

# Python
black . && flake8 . && bandit -r ghidrainsight/

# TypeScript
npm run lint && npm run type-check
```

### Commit Signing

```bash
git config user.signingkey <key-id>
git commit -S -m "feat: add feature"
```

---

## 10. Compliance & Standards

GhidraInsight adheres to:

- **OWASP Top 10** - Web application security
- **CWE/SANS Top 25** - Software weakness classification
- **CVSS v3.1** - Vulnerability scoring

---

## 11. Telemetry & Privacy

### Opt-in Collection

GhidraInsight can collect:
- Feature usage statistics
- Error/crash reports
- Performance metrics

**Disabled by default. Users must explicitly opt-in.**

```yaml
telemetry:
  enabled: false
  endpoint: https://telemetry.ghidrainsight.dev
  batch_interval: 3600
```

### What We DO NOT Collect

- Binary file contents
- Decompiled code
- Function names (by default)
- User credentials or API keys

---

## 12. Incident Response

### Process

1. **Detection** → Incident logged and triaged
2. **Containment** → Affected systems isolated
3. **Eradication** → Vulnerability patched
4. **Recovery** → Systems restored
5. **Post-Incident** → Root cause analysis

### Contact

- **Security Team**: security@ghidrainsight.dev
- **On-Call**: Available 24/7 for critical incidents

---

## 13. Deployment Security

### Docker Security

```dockerfile
# Run as non-root
USER ghidrainsight:ghidrainsight

# Read-only root filesystem
RUN chmod 0755 /app

# Drop unnecessary capabilities
RUN setcap -r /app/bin/*
```

### Kubernetes Security

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: ghidrainsight
spec:
  securityContext:
    runAsNonRoot: true
    readOnlyRootFilesystem: true
  containers:
  - name: ghidrainsight
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop: [ALL]
```

---

## 14. Third-Party Security

### Trusted Partners

- Ghidra (NSA)
- Claude API (Anthropic)
- OpenAI API
- GitHub (hosting + CI/CD)

### Verification

All third-party libraries are:
- Checked for known vulnerabilities
- Regularly updated
- Audited for license compliance

---

## 15. Security Checklist

Before deploying to production:

- [ ] All dependencies updated and audited
- [ ] Secrets stored in secure vault (not in code)
- [ ] TLS/HTTPS enabled
- [ ] Authentication & authorization working
- [ ] Rate limiting configured
- [ ] CORS policy restricted
- [ ] Logging enabled
- [ ] Database encrypted
- [ ] Firewall rules configured
- [ ] Backup & disaster recovery plan
- [ ] Security.txt file created
- [ ] Contact info for security issues published

---

## 16. Versioning

| Version | Supported | End of Life |
|---------|-----------|-------------|
| 1.0.x   | ✅        | Dec 2026   |
| 0.9.x   | ✅        | Jun 2025   |
| 0.8.x   | ❌        | Jun 2024   |

---

## Questions?

For security-related questions (non-vulnerability):
- **Discussions**: [GitHub Discussions](https://github.com/ismailtsdln/GhidraInsight/discussions)
- **Email**: support@ghidrainsight.dev

---

**Last Updated**: January 2026
**Version**: 1.0.0
