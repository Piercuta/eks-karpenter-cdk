# EKS GitOps Infrastructure

Infrastructure AWS complète utilisant CDK pour créer un cluster EKS minimal avec architecture GitOps via ArgoCD.

## 🏗️ Architecture

Cette infrastructure utilise une approche hybride :
- **AWS CDK** : Création du cluster EKS minimal et des rôles IAM
- **ArgoCD** : Gestion de tous les addons et workloads via GitOps
- **Karpenter** : Auto-scaling des nœuds
- **AWS Load Balancer Controller** : Gestion des load balancers

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   AWS CDK       │    │   ArgoCD        │    │   Git Repo      │
│                 │    │                 │    │                 │
│ ┌─────────────┐ │    │ ┌─────────────┐ │    │ ┌─────────────┐ │
│ │ EKS Cluster │ │    │ │ ArgoCD      │ │    │ │ Manifests   │ │
│ │ (Minimal)   │ │    │ │ Server      │ │    │ │ - CoreDNS   │ │
│ │             │ │    │ │             │ │    │ │ - kube-proxy│ │
│ │ IAM Roles   │ │    │ │             │ │    │ │ - ALB Ctrl  │ │
│ │             │ │    │ │             │ │    │ │ - Karpenter │ │
│ │ Outputs     │ │    │ │             │ │    │ │ - MainApi   │ │
│ └─────────────┘ │    │ └─────────────┘ │    │ │ - Ingress   │ │
└─────────────────┘    └─────────────────┘    │ └─────────────┘ │
                                              └─────────────────┘
```

## 🚀 Déploiement Rapide

### Prérequis

- AWS CLI configuré
- CDK installé (`npm install -g aws-cdk`)
- Python 3.8+
- kubectl installé

### Installation

1. **Cloner le repository**
   ```bash
   git clone <repository-url>
   cd cdk-full-infra
   ```

2. **Installer les dépendances**
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # Linux/Mac
   # ou .venv\Scripts\activate  # Windows
   pip install -r requirements.txt
   ```

3. **Déployer l'infrastructure**
   ```bash
   # Déployer tout l'infrastructure
   ./scripts/deploy-eks-cluster.sh dev eu-west-1
   
   # Ou déployer manuellement
   cdk deploy --all
   ```

4. **Récupérer les outputs**
   ```bash
   ./scripts/get-eks-outputs.sh
   ```

## 📋 Composants

### Infrastructure CDK

- **EksV2Cluster** : Cluster EKS minimal sans addons automatiques
- **IAM Roles** : Rôles pour Karpenter, ALB Controller, ArgoCD, etc.
- **Network** : VPC, sous-réseaux, security groups
- **Database** : Aurora PostgreSQL
- **Frontend** : CloudFront + S3
- **CI/CD** : CodeBuild pipelines

### Rôles IAM Créés

1. **EksClusterRole** - Rôle pour le cluster EKS
2. **EksNodeRole** - Rôle pour les nœuds EKS standard
3. **KarpenterNodeRole** - Rôle pour les nœuds gérés par Karpenter
4. **MainApiCodeBuildRole** - Rôle pour CodeBuild MainApi
5. **AlbControllerRole** - Rôle pour AWS Load Balancer Controller
6. **ArgoCDRole** - Rôle pour ArgoCD

## 🔧 Configuration

### Variables d'environnement

```bash
# Exporter les outputs comme variables d'environnement
export EKS_CLUSTER_NAME="piercuta-dev-eks-cluster"
export KARPENTER_NODE_ROLE_ARN="arn:aws:iam::..."
export ALB_CONTROLLER_ROLE_ARN="arn:aws:iam::..."
export ARGOCD_ROLE_ARN="arn:aws:iam::..."
```

### Configuration par environnement

Les configurations sont gérées via des fichiers YAML dans `config/environments/` :

```yaml
# config/environments/dev.yaml
env_name: dev
project_name: piercuta

aws:
  account: "123456789012"
  region: eu-west-1

vpc:
  cidr: "10.0.0.0/16"
  max_azs: 3
  nat_gateways: 1
```

## 🎯 Utilisation avec ArgoCD

### 1. Structure du repo GitOps

```
manifests/
├── argocd/
│   ├── applications/
│   │   ├── coredns.yaml
│   │   ├── kube-proxy.yaml
│   │   ├── aws-load-balancer-controller.yaml
│   │   ├── karpenter.yaml
│   │   └── main-api-app.yaml
│   └── projects/
│       └── default.yaml
├── coredns/
├── karpenter/
├── aws-load-balancer-controller/
└── main-api/
```

### 2. Exemple de manifest Karpenter

```yaml
# manifests/karpenter/nodeclass.yaml
apiVersion: karpenter.k8s.aws/v1beta1
kind: NodeClass
metadata:
  name: default
spec:
  amiFamily: AL2
  role: ${KARPENTER_ROLE_ARN}  # Utilise l'output CDK
  subnetSelectorTerms:
    - tags:
        k8s.io/cluster-autoscaler/node-template/label/node.kubernetes.io/role: worker
```

### 3. Installation d'ArgoCD

```bash
# Installer ArgoCD
kubectl create namespace argocd
kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml

# Récupérer le mot de passe admin
kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d
```

## 📊 Monitoring

### CloudWatch Logs

Tous les logs du cluster sont envoyés vers CloudWatch :
- API Server
- Audit
- Authenticator
- Controller Manager
- Scheduler

### Métriques

- Utilisez CloudWatch Container Insights
- Configurez des alertes sur les métriques critiques

## 🔒 Sécurité

### IAM Roles

- Principe du moindre privilège
- Politiques larges au départ (à affiner selon les besoins)
- Utilisation d'OIDC pour les workloads

### Network Security

- Sous-réseaux privés pour les workloads
- Sous-réseaux publics pour les load balancers
- Security groups configurés pour l'isolation

## 🛠️ Scripts Utilitaires

### Récupération des outputs

```bash
# Récupérer tous les outputs
./scripts/get-eks-outputs.sh

# Récupérer un output spécifique
aws cloudformation describe-stacks \
  --stack-name piercuta-dev-eks-backend-stack \
  --query 'Stacks[0].Outputs[?OutputKey==`ClusterName`].OutputValue' \
  --output text
```

### Déploiement complet

```bash
# Déployer et tester le cluster
./scripts/deploy-eks-cluster.sh dev eu-west-1
```

## 📚 Documentation

- [Architecture GitOps EKS](docs/eks-gitops-architecture.md)
- [Exemples ArgoCD](examples/argocd-applications/)
- [Scripts utilitaires](scripts/)

## 🔄 Maintenance

### Mises à jour

- **Cluster EKS** : Via CDK
- **Addons** : Via ArgoCD
- **Applications** : Via ArgoCD

### Sauvegarde

- Utilisez Velero pour les sauvegardes de cluster
- Sauvegardes automatiques des bases de données RDS

## 🐛 Troubleshooting

### Problèmes courants

1. **Erreurs de permissions IAM**
   - Vérifiez les politiques des rôles
   - Utilisez AWS IAM Access Analyzer

2. **Problèmes de networking**
   - Vérifiez les security groups
   - Testez la connectivité entre sous-réseaux

3. **Problèmes ArgoCD**
   - Vérifiez les logs : `kubectl logs -n argocd -l app.kubernetes.io/name=argocd-server`
   - Vérifiez la synchronisation des applications

## 🤝 Contribution

1. Fork le repository
2. Créez une branche feature
3. Committez vos changements
4. Poussez vers la branche
5. Créez une Pull Request

## 📄 Licence

Ce projet est sous licence MIT. Voir le fichier [LICENSE](LICENSE) pour plus de détails.

## 🔗 Liens Utiles

- [Documentation EKS](https://docs.aws.amazon.com/eks/)
- [Documentation ArgoCD](https://argo-cd.readthedocs.io/)
- [Documentation Karpenter](https://karpenter.sh/)
- [AWS Load Balancer Controller](https://kubernetes-sigs.github.io/aws-load-balancer-controller/)
