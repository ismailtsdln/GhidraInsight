# GCP Deployment Guide

Deploy GhidraInsight on Google Cloud Platform (GCP).

## Prerequisites

- GCP account
- gcloud CLI configured
- kubectl configured
- GKE cluster (or Compute Engine)

## Option 1: GKE (Google Kubernetes Engine)

### 1. Create GKE Cluster

```bash
# Create cluster
gcloud container clusters create ghidrainsight \
  --zone us-central1-a \
  --machine-type n1-standard-4 \
  --num-nodes 3 \
  --enable-autoscaling \
  --min-nodes 2 \
  --max-nodes 5 \
  --enable-autorepair \
  --enable-autoupgrade

# Configure kubectl
gcloud container clusters get-credentials ghidrainsight --zone us-central1-a
```

### 2. Deploy with Helm

```bash
# Install Helm chart
helm install ghidrainsight ./helm \
  --set postgresql.persistence.storageClass=standard-rwo \
  --set ghidraPlugin.resources.requests.memory=8Gi \
  --set ingress.enabled=true \
  --set ingress.className=gce
```

### 3. Configure Ingress

```bash
# Create ingress
kubectl apply -f k8s/ingress.yaml

# Get external IP
kubectl get ingress ghidrainsight-ingress
```

## Option 2: Compute Engine with Docker Compose

### 1. Create VM Instance

```bash
# Create instance
gcloud compute instances create ghidrainsight-vm \
  --zone us-central1-a \
  --machine-type n1-standard-4 \
  --image-family ubuntu-2204-lts \
  --image-project ubuntu-os-cloud \
  --boot-disk-size 50GB \
  --tags http-server,https-server

# Allow HTTP traffic
gcloud compute firewall-rules create allow-http \
  --allow tcp:3000,tcp:8000 \
  --source-ranges 0.0.0.0/0 \
  --target-tags http-server
```

### 2. Install Docker

```bash
# SSH into instance
gcloud compute ssh ghidrainsight-vm --zone us-central1-a

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
```

### 3. Deploy

```bash
# Clone repository
git clone https://github.com/ismailtsdln/GhidraInsight.git
cd GhidraInsight

# Configure environment
cp .env.example .env
# Edit .env

# Start services
docker-compose up -d
```

## Option 3: Cloud Run (Serverless)

### 1. Build and Push Images

```bash
# Configure Docker for GCR
gcloud auth configure-docker

# Build and push
docker build -t gcr.io/PROJECT_ID/ghidrainsight:latest .
docker push gcr.io/PROJECT_ID/ghidrainsight:latest
```

### 2. Deploy to Cloud Run

```bash
# Deploy service
gcloud run deploy ghidrainsight \
  --image gcr.io/PROJECT_ID/ghidrainsight:latest \
  --platform managed \
  --region us-central1 \
  --memory 8Gi \
  --cpu 4 \
  --allow-unauthenticated
```

## Storage

### Cloud SQL for PostgreSQL

```bash
# Create Cloud SQL instance
gcloud sql instances create ghidrainsight-db \
  --database-version POSTGRES_15 \
  --tier db-n1-standard-2 \
  --region us-central1 \
  --storage-type SSD \
  --storage-size 50GB

# Create database
gcloud sql databases create ghidrainsight --instance ghidrainsight-db
```

## Networking

### VPC Configuration

```bash
# Create VPC
gcloud compute networks create ghidrainsight-vpc \
  --subnet-mode custom

# Create subnet
gcloud compute networks subnets create ghidrainsight-subnet \
  --network ghidrainsight-vpc \
  --range 10.0.0.0/24 \
  --region us-central1
```

## Monitoring

### Cloud Monitoring

```bash
# Enable monitoring API
gcloud services enable monitoring.googleapis.com

# View metrics
gcloud monitoring dashboards list
```

## Cost Optimization

- Use Preemptible VMs for non-critical workloads
- Enable Autoscaling
- Use Cloud Storage for binary storage
- Set up budget alerts

## Backup

See [BACKUP_AND_RECOVERY.md](BACKUP_AND_RECOVERY.md) for backup procedures.

## Troubleshooting

```bash
# Check GKE cluster status
gcloud container clusters describe ghidrainsight --zone us-central1-a

# View logs
gcloud logging read "resource.type=gke_cluster" --limit 50

# Check instance status
gcloud compute instances describe ghidrainsight-vm --zone us-central1-a
```
