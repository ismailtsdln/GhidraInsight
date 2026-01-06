# AWS Deployment Guide

Deploy GhidraInsight on Amazon Web Services (AWS).

## Prerequisites

- AWS account
- AWS CLI configured
- kubectl configured
- EKS cluster (or EC2 instances)

## Option 1: EKS (Elastic Kubernetes Service)

### 1. Create EKS Cluster

```bash
# Create cluster
eksctl create cluster \
  --name ghidrainsight \
  --region us-east-1 \
  --node-type m5.2xlarge \
  --nodes 3 \
  --nodes-min 2 \
  --nodes-max 5

# Configure kubectl
aws eks update-kubeconfig --name ghidrainsight --region us-east-1
```

### 2. Deploy with Helm

```bash
# Install Helm chart
helm install ghidrainsight ./helm \
  --set postgresql.persistence.storageClass=gp3 \
  --set ghidraPlugin.resources.requests.memory=8Gi \
  --set ingress.enabled=true \
  --set ingress.hosts[0].host=ghidrainsight.yourdomain.com
```

### 3. Configure Load Balancer

```bash
# Create ALB ingress controller
kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/aws-load-balancer-controller/v2.4.0/docs/install/v2_4_0_full.yaml

# Update ingress
kubectl apply -f k8s/ingress.yaml
```

## Option 2: EC2 with Docker Compose

### 1. Launch EC2 Instance

```bash
# Launch instance (Ubuntu 22.04, t3.xlarge or larger)
aws ec2 run-instances \
  --image-id ami-0c55b159cbfafe1f0 \
  --instance-type t3.xlarge \
  --key-name your-key \
  --security-groups sg-xxxxx \
  --user-data file://scripts/aws-setup.sh
```

### 2. Install Docker

```bash
# SSH into instance
ssh -i your-key.pem ubuntu@<instance-ip>

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker ubuntu

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
# Edit .env with your settings

# Start services
docker-compose up -d
```

## Option 3: ECS (Elastic Container Service)

### 1. Create ECS Cluster

```bash
# Create cluster
aws ecs create-cluster --cluster-name ghidrainsight

# Create task definition (see ecs-task-definition.json)
aws ecs register-task-definition --cli-input-json file://ecs-task-definition.json
```

### 2. Create Service

```bash
aws ecs create-service \
  --cluster ghidrainsight \
  --service-name ghidrainsight-service \
  --task-definition ghidrainsight:1 \
  --desired-count 2 \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={subnets=[subnet-xxx],securityGroups=[sg-xxx],assignPublicIp=ENABLED}"
```

## Storage

### EBS for PostgreSQL

```bash
# Create EBS volume
aws ec2 create-volume \
  --size 50 \
  --volume-type gp3 \
  --availability-zone us-east-1a

# Attach to instance
aws ec2 attach-volume \
  --volume-id vol-xxxxx \
  --instance-id i-xxxxx \
  --device /dev/sdf
```

## Networking

### Security Groups

```yaml
Inbound Rules:
  - Port 3000 (HTTP) from 0.0.0.0/0
  - Port 8000 (API) from VPC only
  - Port 5432 (PostgreSQL) from VPC only
```

## Monitoring

### CloudWatch Integration

```bash
# Install CloudWatch agent
wget https://s3.amazonaws.com/amazoncloudwatch-agent/ubuntu/amd64/latest/amazon-cloudwatch-agent.deb
sudo dpkg -i amazon-cloudwatch-agent.deb

# Configure
sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
  -a fetch-config -m ec2 -c file:cloudwatch-config.json
```

## Cost Optimization

- Use Spot Instances for non-critical workloads
- Enable Auto Scaling
- Use S3 for binary storage
- Enable CloudWatch alarms for cost monitoring

## Backup

See [BACKUP_AND_RECOVERY.md](BACKUP_AND_RECOVERY.md) for backup procedures.

## Troubleshooting

```bash
# Check EKS cluster status
aws eks describe-cluster --name ghidrainsight

# View CloudWatch logs
aws logs tail /aws/ecs/ghidrainsight --follow

# Check ECS service status
aws ecs describe-services --cluster ghidrainsight --services ghidrainsight-service
```
