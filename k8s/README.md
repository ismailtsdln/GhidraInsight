# Kubernetes Deployment

Kubernetes manifests for deploying GhidraInsight to a Kubernetes cluster.

## Prerequisites

- Kubernetes cluster (v1.24+)
- kubectl configured
- PersistentVolume support

## Quick Start

```bash
# Create namespace
kubectl apply -f namespace.yaml

# Create secrets (update password!)
kubectl apply -f postgres-secret.yaml

# Create persistent volume
kubectl apply -f postgres-pvc.yaml

# Deploy PostgreSQL
kubectl apply -f postgres-deployment.yaml

# Deploy GhidraInsight components
kubectl apply -f configmap.yaml
kubectl apply -f ghidra-plugin-deployment.yaml
kubectl apply -f python-mcp-deployment.yaml
kubectl apply -f web-dashboard-deployment.yaml

# Optional: Deploy ingress
kubectl apply -f ingress.yaml
```

## Configuration

Update `configmap.yaml` and `postgres-secret.yaml` with your values before deploying.

## Scaling

```bash
# Scale ghidra-plugin
kubectl scale deployment ghidra-plugin --replicas=3 -n ghidrainsight

# Scale python-mcp
kubectl scale deployment python-mcp --replicas=3 -n ghidrainsight
```

## Monitoring

```bash
# Check pod status
kubectl get pods -n ghidrainsight

# Check logs
kubectl logs -f deployment/ghidra-plugin -n ghidrainsight
kubectl logs -f deployment/python-mcp -n ghidrainsight
```

## Backup

See `../docs/BACKUP_AND_RECOVERY.md` for backup procedures.
