# Backup and Disaster Recovery

Comprehensive backup and recovery procedures for GhidraInsight.

## Overview

GhidraInsight backup strategy includes:
- Database backups (PostgreSQL)
- Configuration backups
- Binary analysis cache backups
- Disaster recovery procedures

## Database Backup

### Automated Backups

#### PostgreSQL (Docker)

```bash
# Create backup script
cat > scripts/backup-db.sh << 'EOF'
#!/bin/bash
BACKUP_DIR="/backups/postgres"
DATE=$(date +%Y%m%d_%H%M%S)
mkdir -p $BACKUP_DIR

# Backup database
docker exec postgres pg_dump -U ghidrauser ghidrainsight | gzip > $BACKUP_DIR/ghidrainsight_$DATE.sql.gz

# Keep only last 30 days
find $BACKUP_DIR -name "*.sql.gz" -mtime +30 -delete
EOF

chmod +x scripts/backup-db.sh

# Add to crontab (daily at 2 AM)
echo "0 2 * * * /path/to/scripts/backup-db.sh" | crontab -
```

#### PostgreSQL (Kubernetes)

```yaml
# k8s/postgres-backup-job.yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: postgres-backup
  namespace: ghidrainsight
spec:
  schedule: "0 2 * * *"  # Daily at 2 AM
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: postgres-backup
            image: postgres:15-alpine
            command:
            - /bin/sh
            - -c
            - |
              pg_dump -h postgres -U ghidrauser ghidrainsight | gzip > /backup/ghidrainsight_$(date +%Y%m%d_%H%M%S).sql.gz
            env:
            - name: PGPASSWORD
              valueFrom:
                secretKeyRef:
                  name: postgres-secret
                  key: password
            volumeMounts:
            - name: backup-storage
              mountPath: /backup
          volumes:
          - name: backup-storage
            persistentVolumeClaim:
              claimName: backup-pvc
          restartPolicy: OnFailure
```

### Manual Backup

```bash
# Docker
docker exec postgres pg_dump -U ghidrauser ghidrainsight > backup.sql

# Kubernetes
kubectl exec -it postgres-xxx -n ghidrainsight -- pg_dump -U ghidrauser ghidrainsight > backup.sql

# Direct connection
pg_dump -h localhost -U ghidrauser ghidrainsight > backup.sql
```

## Database Restore

### From Backup File

```bash
# Docker
gunzip -c backup.sql.gz | docker exec -i postgres psql -U ghidrauser ghidrainsight

# Kubernetes
gunzip -c backup.sql.gz | kubectl exec -i postgres-xxx -n ghidrainsight -- psql -U ghidrauser ghidrainsight

# Direct connection
gunzip -c backup.sql.gz | psql -h localhost -U ghidrauser ghidrainsight
```

## Configuration Backup

### Backup Configuration Files

```bash
# Create backup script
cat > scripts/backup-config.sh << 'EOF'
#!/bin/bash
BACKUP_DIR="/backups/config"
DATE=$(date +%Y%m%d_%H%M%S)
mkdir -p $BACKUP_DIR

# Backup docker-compose.yml
cp docker-compose.yml $BACKUP_DIR/docker-compose_$DATE.yml

# Backup .env files
cp .env $BACKUP_DIR/env_$DATE 2>/dev/null || true

# Backup Kubernetes configs
tar -czf $BACKUP_DIR/k8s_$DATE.tar.gz k8s/ helm/ 2>/dev/null || true

# Keep only last 30 days
find $BACKUP_DIR -type f -mtime +30 -delete
EOF

chmod +x scripts/backup-config.sh
```

## Cloud Storage Backups

### AWS S3

```bash
# Install AWS CLI
pip install awscli

# Configure
aws configure

# Backup to S3
aws s3 sync /backups/postgres s3://ghidrainsight-backups/postgres/
aws s3 sync /backups/config s3://ghidrainsight-backups/config/
```

### Google Cloud Storage

```bash
# Install gsutil
pip install gsutil

# Configure
gcloud auth login

# Backup to GCS
gsutil -m cp -r /backups/postgres gs://ghidrainsight-backups/
gsutil -m cp -r /backups/config gs://ghidrainsight-backups/
```

### Azure Blob Storage

```bash
# Install Azure CLI
az storage blob upload-batch \
  --account-name ghidrainsight \
  --destination backups \
  --source /backups/postgres
```

## Disaster Recovery

### Recovery Procedures

#### 1. Full System Recovery

```bash
# 1. Restore database
gunzip -c backup.sql.gz | psql -h localhost -U ghidrauser ghidrainsight

# 2. Restore configuration
cp /backups/config/docker-compose_YYYYMMDD.yml docker-compose.yml
cp /backups/config/env_YYYYMMDD .env

# 3. Restart services
docker-compose down
docker-compose up -d
```

#### 2. Point-in-Time Recovery

```bash
# Enable WAL archiving in postgresql.conf
wal_level = replica
archive_mode = on
archive_command = 'cp %p /backups/wal/%f'

# Restore to specific time
pg_basebackup -D /restore -Ft -z -P
# Then apply WAL files up to target time
```

#### 3. Multi-Region Recovery

```bash
# Setup replication
# Primary: us-east-1
# Standby: us-west-2

# Promote standby to primary
pg_ctl promote -D /var/lib/postgresql/data
```

## Backup Verification

### Test Restore

```bash
# Create test database
createdb ghidrainsight_test

# Restore backup
gunzip -c backup.sql.gz | psql ghidrainsight_test

# Verify
psql ghidrainsight_test -c "SELECT COUNT(*) FROM binary_analyses;"
```

## Automation

### Backup Monitoring

```python
# scripts/backup-monitor.py
import os
import subprocess
from datetime import datetime, timedelta

def check_backup_age(backup_dir):
    """Check if backups are recent."""
    files = os.listdir(backup_dir)
    if not files:
        return False
    
    latest = max(files, key=lambda f: os.path.getmtime(os.path.join(backup_dir, f)))
    latest_time = datetime.fromtimestamp(os.path.getmtime(os.path.join(backup_dir, latest)))
    
    return datetime.now() - latest_time < timedelta(days=1)

if __name__ == "__main__":
    if not check_backup_age("/backups/postgres"):
        print("WARNING: No recent backup found!")
        # Send alert
```

## Best Practices

1. **Automate Backups**: Use cron jobs or Kubernetes CronJobs
2. **Test Restores**: Regularly test backup restoration
3. **Offsite Storage**: Store backups in cloud storage
4. **Encryption**: Encrypt sensitive backups
5. **Retention Policy**: Keep backups for appropriate duration
6. **Monitoring**: Monitor backup success/failure
7. **Documentation**: Document recovery procedures

## Recovery Time Objectives (RTO)

- **Database**: < 1 hour
- **Configuration**: < 15 minutes
- **Full System**: < 4 hours

## Recovery Point Objectives (RPO)

- **Database**: < 24 hours (daily backups)
- **Configuration**: < 1 hour (version control)
- **Cache**: Acceptable to lose (can regenerate)
