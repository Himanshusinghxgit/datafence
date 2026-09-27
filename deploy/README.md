# Deployment Guide

Complete guide for deploying DataFence in various environments.

## Deployment Options

1. **Docker** - Single container deployment
2. **Docker Compose** - Multi-container local setup
3. **Kubernetes** - Production orchestration
4. **AWS** - ECS, EKS, Lambda
5. **Cloud Run** - Google Cloud serverless

## Docker Deployment

### Build

```bash
docker build -t datafence-api:latest .
```

### Run

```bash
docker run -d \
  -p 8000:8000 \
  -e DATAFENCE_POSTGRES_HOST=db.example.com \
  -e DATAFENCE_POSTGRES_DATABASE=datafence \
  -e DATAFENCE_POSTGRES_USER=datafence \
  -e DATAFENCE_POSTGRES_PASSWORD=secret \
  -e API_KEY=your-api-key \
  -v $(pwd)/policy.yaml:/app/policy.yaml:ro \
  --name datafence-api \
  datafence-api:latest
```

## Docker Compose Deployment

### Development

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f datafence-api

# Stop
docker-compose down
```

### Production

```bash
# Use production compose file
docker-compose -f docker-compose.prod.yml up -d
```

## Kubernetes Deployment

See [kubernetes/README.md](../kubernetes/README.md) for detailed instructions.

### Quick Deploy

```bash
kubectl create namespace datafence
kubectl apply -f kubernetes/ -n datafence
```

## AWS Deployment

### ECS (Fargate)

1. Push image to ECR
2. Create task definition
3. Create service
4. Configure load balancer

```bash
# Push to ECR
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin <account>.dkr.ecr.us-east-1.amazonaws.com
docker tag datafence-api:latest <account>.dkr.ecr.us-east-1.amazonaws.com/datafence-api:latest
docker push <account>.dkr.ecr.us-east-1.amazonaws.com/datafence-api:latest

# Create task definition (use AWS Console or Terraform)
```

### EKS

Use Kubernetes manifests with EKS:

```bash
# Configure kubectl
aws eks update-kubeconfig --region us-east-1 --name my-cluster

# Deploy
kubectl apply -f kubernetes/ -n datafence
```

### Lambda (Serverless)

For lighter workloads:

```python
# lambda_handler.py
from datafence import DataFence
from datafence.connectors import PostgreSQLConnector

connector = PostgreSQLConnector(...)
fence = DataFence.from_yaml("policy.yaml", connector)

def lambda_handler(event, context):
    request = event['body']
    result = fence.execute(request)
    return {
        'statusCode': 200 if result.verified else 403,
        'body': json.dumps({
            'data': result.data if result.verified else None
        })
    }
```

## Google Cloud Deployment

### Cloud Run

```bash
# Build and push to GCR
gcloud builds submit --tag gcr.io/PROJECT_ID/datafence-api

# Deploy
gcloud run deploy datafence-api \
  --image gcr.io/PROJECT_ID/datafence-api \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated \
  --set-env-vars DATAFENCE_POSTGRES_HOST=... \
  --set-secrets DATAFENCE_POSTGRES_PASSWORD=postgres-password:latest
```

### GKE

Use Kubernetes manifests with GKE:

```bash
# Configure kubectl
gcloud container clusters get-credentials my-cluster --region us-central1

# Deploy
kubectl apply -f kubernetes/ -n datafence
```

## Azure Deployment

### Container Instances

```bash
az container create \
  --resource-group myResourceGroup \
  --name datafence-api \
  --image datafence-api:latest \
  --ports 8000 \
  --environment-variables \
    DATAFENCE_POSTGRES_HOST=... \
  --secure-environment-variables \
    DATAFENCE_POSTGRES_PASSWORD=... \
    API_KEY=...
```

### AKS

Use Kubernetes manifests with AKS.

## Environment Variables

### Required

- `DATAFENCE_POSTGRES_HOST` - Database host
- `DATAFENCE_POSTGRES_DATABASE` - Database name
- `DATAFENCE_POSTGRES_USER` - Database user
- `DATAFENCE_POSTGRES_PASSWORD` - Database password
- `API_KEY` - API authentication key

### Optional

- `DATAFENCE_POSTGRES_PORT` - Database port (default: 5432)
- `LOG_LEVEL` - Logging level (default: INFO)
- `LOG_FORMAT` - Log format: json or text (default: json)
- `WORKERS` - Number of workers (default: 4)

## Health Checks

All deployments should configure health checks:

- **Liveness**: `GET /healthz`
- **Readiness**: `GET /ready`
- **Health**: `GET /health` (comprehensive)

## SSL/TLS

### Let's Encrypt (Kubernetes)

cert-manager automatically provisions certificates:

```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: admin@example.com
    privateKeySecretRef:
      name: letsencrypt-prod
    solvers:
    - http01:
        ingress:
          class: nginx
```

### Manual Certificate

Mount certificate files:

```bash
docker run -d \
  -v /path/to/cert.pem:/app/cert.pem:ro \
  -v /path/to/key.pem:/app/key.pem:ro \
  datafence-api:latest
```

## Backup and Recovery

### Policy Backup

```bash
# Backup ConfigMap
kubectl get configmap datafence-policy -n datafence -o yaml > policy-backup.yaml

# Restore
kubectl apply -f policy-backup.yaml
```

### Database Backup

```bash
# PostgreSQL backup
pg_dump -h localhost -U datafence datafence > backup.sql

# Restore
psql -h localhost -U datafence datafence < backup.sql
```

## Monitoring Setup

### Prometheus

```yaml
# ServiceMonitor for Prometheus Operator
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: datafence-api
  namespace: datafence
spec:
  selector:
    matchLabels:
      app: datafence
  endpoints:
  - port: http
    path: /metrics
```

### Grafana

Import dashboard from `monitoring/grafana/dashboards/datafence.json`

## Rolling Updates

### Kubernetes

```bash
# Update image
kubectl set image deployment/datafence-api \
  datafence-api=datafence-api:v1.1.0 \
  -n datafence

# Monitor rollout
kubectl rollout status deployment/datafence-api -n datafence

# Rollback if needed
kubectl rollout undo deployment/datafence-api -n datafence
```

### Docker

```bash
# Pull new image
docker pull datafence-api:v1.1.0

# Stop old container
docker stop datafence-api

# Start new container
docker run -d --name datafence-api datafence-api:v1.1.0 ...
```

## Production Checklist

### Security
- [ ] Use secrets management (Vault, AWS Secrets Manager)
- [ ] Enable TLS/SSL
- [ ] Use strong API keys
- [ ] Configure network policies
- [ ] Enable pod security policies
- [ ] Run as non-root user
- [ ] Read-only root filesystem

### Reliability
- [ ] Set up health checks
- [ ] Configure autoscaling
- [ ] Set resource limits
- [ ] Enable pod disruption budgets
- [ ] Configure graceful shutdown
- [ ] Set up load balancing

### Observability
- [ ] Configure structured logging
- [ ] Set up metrics collection
- [ ] Create dashboards
- [ ] Configure alerting
- [ ] Enable distributed tracing
- [ ] Set up audit logging

### Performance
- [ ] Tune connection pool sizes
- [ ] Configure caching
- [ ] Set appropriate resource limits
- [ ] Enable compression
- [ ] Use CDN for static assets

### Operations
- [ ] Document deployment process
- [ ] Create runbooks
- [ ] Set up CI/CD pipelines
- [ ] Configure backup and recovery
- [ ] Test disaster recovery
- [ ] Plan capacity

## Troubleshooting

### Container Won't Start

```bash
# Check logs
docker logs datafence-api

# Check configuration
docker inspect datafence-api
```

### High Memory Usage

```bash
# Check memory limits
kubectl describe pod <pod-name> -n datafence

# Increase limits in deployment.yaml
resources:
  limits:
    memory: 1Gi
```

### Database Connection Errors

```bash
# Test connectivity
kubectl run -it --rm debug --image=postgres:15 --restart=Never -n datafence -- \
  psql -h $DB_HOST -U $DB_USER -d $DB_NAME

# Check credentials
kubectl get secret datafence-db-credentials -n datafence -o jsonpath='{.data}'
```

## Support

For deployment issues:
- Check [GitHub Issues](https://github.com/yourusername/datafence/issues)
- See [docs/](../docs/) for detailed documentation
- Review [examples/](../examples/) for sample configurations
