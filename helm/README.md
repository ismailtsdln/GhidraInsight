# GhidraInsight Helm Chart

Helm chart for deploying GhidraInsight to Kubernetes.

## Installation

```bash
# Add repository (if published)
helm repo add ghidrainsight https://charts.ghidrainsight.dev
helm repo update

# Install
helm install ghidrainsight ghidrainsight/ghidrainsight

# Or install from local chart
helm install ghidrainsight ./helm
```

## Configuration

See `values.yaml` for all configurable options.

### Example: Custom Configuration

```yaml
ghidraPlugin:
  replicaCount: 3
  resources:
    requests:
      memory: "8Gi"
      cpu: "4"

pythonMcp:
  replicaCount: 3

postgresql:
  persistence:
    size: 50Gi
```

## Upgrade

```bash
helm upgrade ghidrainsight ./helm
```

## Uninstall

```bash
helm uninstall ghidrainsight
```

## Values

| Parameter | Description | Default |
|-----------|-------------|---------|
| `ghidraPlugin.replicaCount` | Number of ghidra-plugin replicas | `2` |
| `pythonMcp.replicaCount` | Number of python-mcp replicas | `2` |
| `webDashboard.replicaCount` | Number of web-dashboard replicas | `2` |
| `postgresql.persistence.size` | PostgreSQL storage size | `20Gi` |
| `ingress.enabled` | Enable ingress | `false` |
