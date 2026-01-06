# Azure Deployment Guide

Deploy GhidraInsight on Microsoft Azure.

## Prerequisites

- Azure account
- Azure CLI configured
- kubectl configured
- AKS cluster (or Virtual Machines)

## Option 1: AKS (Azure Kubernetes Service)

### 1. Create AKS Cluster

```bash
# Create resource group
az group create --name ghidrainsight-rg --location eastus

# Create AKS cluster
az aks create \
  --resource-group ghidrainsight-rg \
  --name ghidrainsight \
  --node-count 3 \
  --node-vm-size Standard_D4s_v3 \
  --enable-managed-identity \
  --enable-addons monitoring

# Configure kubectl
az aks get-credentials --resource-group ghidrainsight-rg --name ghidrainsight
```

### 2. Deploy with Helm

```bash
# Install Helm chart
helm install ghidrainsight ./helm \
  --set postgresql.persistence.storageClass=managed-premium \
  --set ghidraPlugin.resources.requests.memory=8Gi \
  --set ingress.enabled=true \
  --set ingress.className=nginx
```

### 3. Configure Ingress

```bash
# Install NGINX ingress controller
helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx
helm install ingress-nginx ingress-nginx/ingress-nginx

# Create ingress
kubectl apply -f k8s/ingress.yaml
```

## Option 2: Virtual Machines with Docker Compose

### 1. Create VM

```bash
# Create resource group
az group create --name ghidrainsight-rg --location eastus

# Create VM
az vm create \
  --resource-group ghidrainsight-rg \
  --name ghidrainsight-vm \
  --image Ubuntu2204 \
  --size Standard_D4s_v3 \
  --admin-username azureuser \
  --generate-ssh-keys \
  --public-ip-sku Standard

# Open ports
az vm open-port --port 3000 --resource-group ghidrainsight-rg --name ghidrainsight-vm
az vm open-port --port 8000 --resource-group ghidrainsight-rg --name ghidrainsight-vm
```

### 2. Install Docker

```bash
# SSH into VM
ssh azureuser@<public-ip>

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker azureuser

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

## Option 3: Container Instances

### 1. Create Container Group

```bash
# Create container group
az container create \
  --resource-group ghidrainsight-rg \
  --name ghidrainsight \
  --image ghidrainsight/ghidrainsight:latest \
  --cpu 4 \
  --memory 8 \
  --ports 3000 8000 \
  --ip-address Public
```

## Storage

### Azure Database for PostgreSQL

```bash
# Create PostgreSQL server
az postgres flexible-server create \
  --resource-group ghidrainsight-rg \
  --name ghidrainsight-db \
  --location eastus \
  --admin-user ghidrauser \
  --admin-password YourPassword123! \
  --sku-name Standard_D2s_v3 \
  --tier GeneralPurpose \
  --storage-size 50 \
  --version 15

# Create database
az postgres flexible-server db create \
  --resource-group ghidrainsight-rg \
  --server-name ghidrainsight-db \
  --database-name ghidrainsight
```

## Networking

### Virtual Network

```bash
# Create virtual network
az network vnet create \
  --resource-group ghidrainsight-rg \
  --name ghidrainsight-vnet \
  --address-prefix 10.0.0.0/16 \
  --subnet-name ghidrainsight-subnet \
  --subnet-prefix 10.0.1.0/24
```

## Monitoring

### Azure Monitor

```bash
# Enable monitoring
az monitor log-analytics workspace create \
  --resource-group ghidrainsight-rg \
  --workspace-name ghidrainsight-workspace

# View logs
az monitor log-analytics query \
  --workspace ghidrainsight-workspace \
  --analytics-query "ContainerInstanceLog_CL | take 10"
```

## Cost Optimization

- Use Spot VMs for non-critical workloads
- Enable Autoscaling
- Use Blob Storage for binary storage
- Set up budget alerts

## Backup

See [BACKUP_AND_RECOVERY.md](BACKUP_AND_RECOVERY.md) for backup procedures.

## Troubleshooting

```bash
# Check AKS cluster status
az aks show --resource-group ghidrainsight-rg --name ghidrainsight

# View logs
az container logs --resource-group ghidrainsight-rg --name ghidrainsight

# Check VM status
az vm show --resource-group ghidrainsight-rg --name ghidrainsight-vm
```
