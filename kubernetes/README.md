# Kubernetes Deployment Guide

Deploy DataFence to Kubernetes.

## Quick Start

```bash
# Create namespace
kubectl create namespace datafence

# Apply all manifests
kubectl apply -f kubernetes/ -n datafence

# Check status
kubectl get pods -n datafence
kubectl get svc -n datafence
```

## Files

- `deployment.yaml` - Main API deployment (3 replicas)
- `service.yaml` - ClusterIP service
- `ingress.yaml` - Ingress with TLS
- `configmap.yaml` - Policy configuration
- `secrets.yaml` - Database credentials and API keys
- `hpa.yaml` - Horizontal Pod Autoscaler (3-10 replicas)
- `rbac.yaml` - ServiceAccount and RBAC

## Prerequisites

1. Kubernetes cluster (1.24+)
2. Ingress controller (nginx)
3. cert-manager (for TLS)
4. PostgreSQL database

## Configuration

### 1. Update Secrets

**⚠️ IMPORTANT:** Change default passwords in `secrets.yaml`

```bash
# Generate secure API key
openssl rand -base64 32

# Update secrets.yaml with real values
kubectl apply -f kubernetes/secrets.yaml -n datafence
```

### 2. Update ConfigMap

Edit `configmap.yaml` with your policy:

```yaml
data:
  policy.yaml: |
    version: "1"
    policy:
      name: your-policy
      # ... your policy here
```

### 3. Update Ingress

Edit `ingress.yaml` with your domain:

```yaml
spec:
  tls:
  - hosts:
    - your-domain.com
  rules:
  - host: your-domain.com
```

## Deployment

```bash
# Apply in order
kubectl apply -f kubernetes/configmap.yaml -n datafence
kubectl apply -f kubernetes/secrets.yaml -n datafence
kubectl apply -f kubernetes/deployment.yaml -n datafence
kubectl apply -f kubernetes/service.yaml -n datafence
kubectl apply -f kubernetes/hpa.yaml -n datafence
kubectl apply -f kubernetes/ingress.yaml -n datafence

# Wait for rollout
kubectl rollout status deployment/datafence-api -n datafence
```

## Verification

```bash
# Check pods
kubectl get pods -n datafence -w

# Check logs
kubectl logs -f deployment/datafence-api -n datafence

# Check health
kubectl port-forward svc/datafence-api 8000:80 -n datafence
curl http://localhost:8000/health

# Test endpoint
curl https://your-domain.com/health
```

## Scaling

### Manual Scaling

```bash
kubectl scale deployment/datafence-api --replicas=5 -n datafence
```

### Autoscaling

HPA automatically scales based on CPU/memory:

```bash
# Check HPA status
kubectl get hpa -n datafence

# View HPA details
kubectl describe hpa datafence-api -n datafence
```

## Monitoring

```bash
# View metrics
kubectl top pods -n datafence

# Prometheus metrics
kubectl port-forward svc/datafence-api 8000:80 -n datafence
curl http://localhost:8000/metrics
```

## Troubleshooting

### Pods not starting

```bash
kubectl describe pod <pod-name> -n datafence
kubectl logs <pod-name> -n datafence
```

### Database connection issues

```bash
# Check secrets
kubectl get secret datafence-db-credentials -n datafence -o yaml

# Test connection
kubectl run -it --rm debug --image=postgres:15 --restart=Never -n datafence -- \
  psql -h <host> -U datafence -d datafence
```

### Ingress not working

```bash
# Check ingress
kubectl describe ingress datafence-api -n datafence

# Check cert-manager
kubectl get certificate -n datafence
kubectl describe certificate datafence-api-tls -n datafence
```

## Production Checklist

- [ ] Update all secrets with production values
- [ ] Configure external database (not in-cluster)
- [ ] Set up monitoring (Prometheus/Grafana)
- [ ] Configure log aggregation
- [ ] Set resource limits appropriately
- [ ] Enable pod security policies
- [ ] Set up backup for policies
- [ ] Configure network policies
- [ ] Enable TLS with valid certificates
- [ ] Set up alerting
