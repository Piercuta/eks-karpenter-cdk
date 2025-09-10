"""
Configuration Management Module

This module defines the configuration structure for AWS CDK infrastructure.
It uses Pydantic for data validation and dependency management.

Structure:
- BaseConfig: Base class with common functionality
- AWS Configuration: AwsConfig, VpcConfig
- Application Configuration: BackendConfig, FrontendConfig
- Database Configuration: DatabaseConfig
- CICD Configuration: CICDFronendConfig, CICDBackendConfig
- DNS Configuration: DnsConfig

Configurations can be overridden via YAML files per environment.
Example file structure:
```
config/
  └── environments/
      ├── dev.yaml
      ├── staging.yaml
      └── prod.yaml

```
"""

from typing import Dict, Any, Optional
from pydantic import BaseModel, Field, model_validator
from aws_cdk import Tags, Stack
from .enums import (
    AwsRegion,
    EnvironmentName
)


class BaseConfig(BaseModel):
    """
    Base configuration with common methods.

    This class provides basic functionality like tag management
    and resource prefix generation.

    Attributes:
        env_name: Deployment environment (dev, prod, etc.)
        project_name: Project name
    """
    env_name: EnvironmentName
    project_name: str

    @property
    def env_name_str(self) -> str:
        """Returns the environment name as a string."""
        return self.env_name.value

    def prefix(self, base: str) -> str:
        """Generates a standardized prefix for resources."""
        return f"{self.project_name}-{self.env_name_str}-{base}"

    def add_stack_global_tags(self, stack: Stack):
        """Adds global tags to the configuration."""
        for key, value in self.tags.items():
            Tags.of(stack).add(key, value)

    @property
    def tags(self):
        """Standardized tags to apply to all resources."""
        return {
            "EnvName": self.env_name_str,
            "ProjectName": self.project_name,
            "ManagedBy": "CDK"
        }


class AwsConfig(BaseModel):
    """
    Base AWS configuration.

    Defines fundamental parameters for AWS access.

    Attributes:
        account: AWS account ID
        region: AWS deployment region
    """
    account: str
    region: AwsRegion

    @property
    def region_str(self) -> str:
        """Returns the region as a string."""
        return self.region.value


class VpcConfig(BaseModel):
    """
    VPC network configuration.

    Defines parameters for the private virtual network.

    Attributes:
        cidr: IP address range (default: "10.0.0.0/16")
        max_azs: Maximum number of availability zones (default: 3)
        reserved_azs: Number of reserved zones (default: 3)
        nat_gateways: Number of NAT Gateways (default: 1)
        automatic_subnet_creation: Enable automatic subnet creation (default: True)
    """
    cidr: str = "10.0.0.0/16"
    max_azs: int = 3
    reserved_azs: int = 3
    nat_gateways: int = 1
    automatic_subnet_creation: bool = True


class DatabaseConfig(BaseModel):
    """
    RDS database configuration.

    Defines parameters for PostgreSQL/Aurora database.

    Attributes:
        snapshot_identifier: Snapshot identifier for restoration (optional)
        backup_retention: Backup retention period in days (default: 2)
        instance_reader: Enable read-only instance (default: False)
        serverless_v2_min_capacity: Minimum capacity in ACU (default: 0.5)
        serverless_v2_max_capacity: Maximum capacity in ACU (default: 2.0)
        master_username: Administrator username (default: "postgres")
        engine: Database engine type (default: POSTGRES)
    """
    snapshot_identifier: Optional[str] = None
    snapshot_on_deletion: bool = True
    backup_retention: int = 2
    instance_reader: bool = False
    serverless_v2_min_capacity: float = Field(
        default=0.5,
        ge=0.5,
        description="Minimum capacity in ACU (minimum 0.5)"
    )
    serverless_v2_max_capacity: float = Field(
        default=2.0,
        description="Maximum capacity in ACU"
    )
    master_username: str = "postgres"

    @model_validator(mode='after')
    def validate_capacity(self) -> 'DatabaseConfig':
        """Validates that minimum capacity is less than maximum capacity."""
        if self.serverless_v2_min_capacity >= self.serverless_v2_max_capacity:
            raise ValueError(
                f"serverless_v2_min_capacity ({self.serverless_v2_min_capacity}) "
                f"must be less than serverless_v2_max_capacity ({self.serverless_v2_max_capacity})"
            )
        return self


class NodeGroupConfig(BaseModel):
    """
    Node group configuration.
    """

    instance_type: str = "m5.large"
    min_size: int = 1
    max_size: int = 2
    desired_size: int = 1


class EksConfig(BaseModel):
    """
    EKS network configuration.

    Defines parameters for the private virtual network.

    Attributes:
        cluster_version: EKS cluster version (default: "1.32")
        node_group: Node group configuration (default: NodeGroupConfig())
    """
    cluster_version: str = "1.32"
    node_group: NodeGroupConfig = NodeGroupConfig()


class GithubConfig(BaseModel):

    connection_arn: str = Field(
        default="arn:aws:codeconnections:eu-west-1:532673134317:connection/2a30a395-8d38-43ab-827b-f39a83c9986a",
        pattern=r"^arn:aws:codeconnections:[a-z0-9-]+:\d{12}:connection/[a-zA-Z0-9-]+$",
        description="GitHub connection ARN"
    )
    owner: str = "Piercuta"
    repo: str = "full-stack-fastapi-backend"
    branch: str = "dev"


class CICDK8SFastAPIConfig(BaseModel):
    """
    ECS backend configuration.

    Defines parameters for ECS Fargate service, including task configuration,
    auto-scaling, and deployment parameters.

    Attributes:
        task_cpu: CPU allocated to the task (default: CPU_256)
        task_memory: Memory allocated to the task (default: MEM_512)
        desired_count: Desired number of instances (default: 1)
        certificate_arn: ACM certificate ARN for HTTPS
        container_env_vars: Container environment variables
        auto_scaling_min_capacity: Minimum auto-scaling capacity (default: 1)
        auto_scaling_max_capacity: Maximum auto-scaling capacity (default: 5)
        ecr_repository_name: ECR repository name
        ecr_image_tag: Docker image tag
    """
    cpu_capacity: str = "500m"
    mem_capacity: str = "512Mi"
    replicas: int = 1
    certificate_arn: str = Field(
        default="arn:aws:acm:eu-west-1:532673134317:certificate/905d0d16-87e8-4e89-a88c-b6053f472e81",
        pattern=r"^arn:aws:acm:[a-z0-9-]+:\d{12}:certificate/[a-zA-Z0-9-]+$",
        description="ACM certificate ARN for backend"
    )
    container_env_vars: Dict[str, str] = Field(default_factory=dict)
    min_replicas: int = Field(
        default=2,
        ge=1,
        description="Minimum auto-scaling capacity (minimum 1)"
    )
    max_replicas: int = Field(
        default=5,
        description="Maximum auto-scaling capacity"
    )
    ecr_repository_name: str = "services/ecs/fastapi_app"
    ecr_image_tag: str = "lastest"

    github: GithubConfig = GithubConfig()

    @model_validator(mode='after')
    def validate_hpa_replicas(self) -> 'K8SFastAPI':
        """Validates that minimum auto-scaling capacity is less than maximum capacity."""
        if self.min_replicas >= self.max_replicas:
            raise ValueError(
                f"min_replicas ({self.min_replicas}) "
                f"must be less than max_replicas ({self.max_replicas})"
            )
        return self


class CICDK8SFileServiceConfig(BaseModel):
    """
    EKS file service configuration.
    """
    cpu_capacity: str = "1000m"
    mem_capacity: str = "512Mi"
    replicas: int = 1

    ecr_repository_name: str = "services/eks/file-service"
    ecr_image_tag: str = "dev"

    github: GithubConfig = GithubConfig()


class FrontendConfig(BaseModel):
    """
    CloudFront frontend configuration.

    Defines parameters for CloudFront distribution and SSL certificate.

    Attributes:
        domain_name: Frontend domain name
        certificate_arn: ACM certificate ARN
        certificate_provider: Certificate provider (default: ACM)
    """
    domain_name: str = f"dev-frontend.piercuta.com"
    certificate_arn: str = Field(
        default="arn:aws:acm:us-east-1:532673134317:certificate/0755fa69-6f18-451a-8987-d98c395089b9",
        pattern=r"^arn:aws:acm:[a-z0-9-]+:\d{12}:certificate/[a-zA-Z0-9-]+$",
        description="ACM certificate ARN for frontend"
    )
    certificate_provider: str = "acm"


class CICDFrontendConfig(BaseModel):
    """
    CI/CD pipeline configuration.

    Defines parameters for continuous deployment pipeline.

    Attributes:
        github: GithubConfig
    """
    github: GithubConfig = GithubConfig()


class DnsConfig(BaseModel):
    """
    DNS configuration.

    Defines parameters for DNS management with Route53.

    Attributes:
        hosted_zone_id: Route53 hosted zone ID
        zone_name: DNS zone name
        frontend_domain_name: Frontend domain name
        fastapi_domain_name: Backend domain name
    """
    hosted_zone_id: str = "Z0068506UV3AK4JBKP59"
    zone_name: str = "piercuta.com"
    frontend_domain_name: str = "dev-frontend.piercuta.com"
    fastapi_domain_name: str = "dev-fastapi.piercuta.com"
    argocd_domain_name: str = "dev-argocd.piercuta.com"


class InfrastructureConfig(BaseConfig):
    """
    Complete infrastructure configuration.

    This class groups all configurations needed to deploy
    the complete infrastructure.

    Attributes:
        aws: Base AWS configuration
        vpc: VPC network configuration
        database: Database configuration
        cicd_k8s_fastapi: CI/CD pipeline configuration
        frontend: CloudFront frontend configuration
        cicd_frontend: CI/CD pipeline configuration
        dns: DNS configuration

    Example:
        ```yaml
        # config/environments/dev.yaml
        env_name: dev
        project_name: my-project

        aws:
          account: "123456789012"
          region: eu-west-1

        vpc:
          cidr: "10.0.0.0/16"
          max_azs: 3
          nat_gateways: 1

        database:
          backup_retention: 7
          serverless_v2_min_capacity: 0.5
          serverless_v2_max_capacity: 2.0

        cicd_k8s_fastapi:
          task_cpu: CPU_512
          task_memory: MEM_1024
          desired_count: 2
          auto_scaling_min_capacity: 1
          auto_scaling_max_capacity: 5

        frontend:
          domain_name: "dev-app.example.com"
          certificate_arn: "arn:aws:acm:..."

        cicd_frontend:
          github:
            owner: "my-org"
            repo: "frontend"
            branch: "dev"


        dns:
          hosted_zone_id: "Z1234567890"
          zone_name: "example.com"
        ```
    """
    aws: AwsConfig
    vpc: VpcConfig
    database: DatabaseConfig
    eks: EksConfig
    cicd_k8s_fastapi: CICDK8SFastAPIConfig
    cicd_k8s_file_service: CICDK8SFileServiceConfig
    frontend: FrontendConfig
    cicd_frontend: CICDFrontendConfig
    dns: DnsConfig
