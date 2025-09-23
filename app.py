#!/usr/bin/env python3
from aws_cdk import App, Environment
from stacks.network_stack import NetworkStack
from stacks.frontend_stack import FrontendStack
from stacks.database_stack import DatabaseStack
from stacks.security_stack import SecurityStack
from config.loader import ConfigLoader
from stacks.dns_stack import DnsStack
from stacks.cicd_frontend_stack import CICDFrontendStack
from stacks.eks_backend_stack import EksBackendStack
from stacks.cicd_k8s_main_api_stack import CICDK8sMainAPIStack
from stacks.cicd_k8s_deploy_stack import CICDK8sDeployStack
from stacks.cicd_k8s_media_api_stack import CICDK8sMediaAPIStack
from stacks.media_stack import MediaStack
app = App()

env_name = app.node.try_get_context('env') or 'dev'
project_name = app.node.try_get_context('project') or 'piercuta'
# Load configuration
config_loader = ConfigLoader(env_name, project_name)
config = config_loader.create_config()


# Create stacks in the correct order
network_stack = NetworkStack(
    app,
    "NetworkStack",
    stack_name=config.prefix("network-stack"),
    env=Environment(
        account=config.aws.account,
        region=config.aws.region_str
    ),
    config=config
)

security_stack = SecurityStack(
    app,
    "SecurityStack",
    stack_name=config.prefix("security-stack"),
    vpc=network_stack.vpc,
    env=Environment(
        account=config.aws.account,
        region=config.aws.region_str
    ),
    config=config
)

database_stack = DatabaseStack(
    app,
    "DatabaseStack",
    stack_name=config.prefix("database-stack"),
    vpc=network_stack.vpc,
    rds_subnets=network_stack.rds_subnets,
    rds_sg=security_stack.rds_security_group,
    rds_lambda_sg=security_stack.rds_lambda_security_group,
    rds_lambda_subnets=network_stack.rds_lambda_subnets,
    env=Environment(
        account=config.aws.account,
        region=config.aws.region_str
    ),
    config=config
)

eks_backend_stack = EksBackendStack(
    app,
    "EksBackendStack",
    stack_name=config.prefix("eks-backend-stack"),
    vpc=network_stack.vpc,
    public_subnets=network_stack.public_subnets,
    eks_private_nat_subnets=network_stack.eks_private_nat_subnets,
    eks_workload_sg=security_stack.eks_workload_sg,
    eks_main_api_sg=security_stack.eks_main_api_sg,
    alb_security_group=security_stack.alb_security_group,
    eks_cluster_additional_sg=security_stack.eks_cluster_additional_sg,
    db_endpoint=database_stack.db_endpoint,
    db_secret_arn=database_stack.db_secret_arn,
    env=Environment(
        account=config.aws.account,
        region=config.aws.region_str
    ),
    config=config
)

frontend_stack = FrontendStack(
    app,
    "FrontendStack",
    stack_name=config.prefix("frontend-stack"),
    env=Environment(
        account=config.aws.account,
        region=config.aws.region_str
    ),
    config=config
)

media_stack = MediaStack(
    app,
    "MediaStack",
    stack_name=config.prefix("media-stack"),
    env=Environment(
        account=config.aws.account,
        region=config.aws.region_str
    ),
    config=config
)

cicd_frontend_stack = CICDFrontendStack(
    app,
    "CICDFrontendStack",
    stack_name=config.prefix("cicd-frontend-stack"),
    static_website=frontend_stack.static_website,
    env=Environment(
        account=config.aws.account,
        region=config.aws.region_str
    ),
    config=config,
)

cicd_k8s_main_api_stack = CICDK8sMainAPIStack(
    app,
    "CICDK8sMainAPIStack",
    stack_name=config.prefix("cicd-k8s-main-api-stack"),
    eks_cluster=eks_backend_stack.eks_cluster,
    db_endpoint=database_stack.db_endpoint,
    eks_main_api_sg=security_stack.eks_main_api_sg,
    alb_sg=security_stack.alb_security_group,
    karpenter_node_role=eks_backend_stack.karpenter_node_role,
    db_secret_arn=database_stack.db_secret_arn,
    env=Environment(
        account=config.aws.account,
        region=config.aws.region_str
    ),
    config=config,
)

cicd_k8s_main_api_stack.add_dependency(eks_backend_stack)

cicd_k8s_media_api_stack = CICDK8sMediaAPIStack(
    app,
    "CICDK8sMediaAPIStack",
    stack_name=config.prefix("cicd-k8s-media-api-stack"),
    eks_cluster=eks_backend_stack.eks_cluster,
    eks_workload_sg=security_stack.eks_workload_sg,
    bucket_distribution_name=media_stack.bucket_distribution.bucket_name,
    env=Environment(
        account=config.aws.account,
        region=config.aws.region_str
    ),
    config=config,
)

cicd_k8s_media_api_stack.add_dependency(eks_backend_stack)
cicd_k8s_media_api_stack.add_dependency(media_stack)

cicd_k8s_deploy_stack = CICDK8sDeployStack(
    app,
    "CICDK8sDeployStack",
    stack_name=config.prefix("cicd-k8s-deploy-stack"),
    eks_cluster_name=eks_backend_stack.eks_cluster.name,
    vpc_id=network_stack.vpc.vpc_id,
    karpenter_node_role=eks_backend_stack.karpenter_node_role,
    eks_node_role=eks_backend_stack.node_role,
    alb_sg=security_stack.alb_security_group,
    env=Environment(
        account=config.aws.account,
        region=config.aws.region_str
    ),
    config=config,
)

cicd_k8s_deploy_stack.add_dependency(cicd_k8s_main_api_stack)
cicd_k8s_deploy_stack.add_dependency(cicd_frontend_stack)
cicd_k8s_deploy_stack.add_dependency(cicd_k8s_media_api_stack)

dns_stack = DnsStack(
    app,
    "DnsStack",
    stack_name=config.prefix("dns-stack"),
    distribution=frontend_stack.static_website.distribution,
    env=Environment(
        account=config.aws.account,
        region=config.aws.region_str
    ),
    config=config
)

dns_stack.add_dependency(cicd_k8s_deploy_stack)


app.synth()
