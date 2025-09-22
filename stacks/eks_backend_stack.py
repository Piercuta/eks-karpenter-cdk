from aws_cdk import Stack, Duration
from aws_cdk import aws_ec2 as ec2
from aws_cdk import aws_eks as eks
from aws_cdk import aws_iam as iam
from constructs import Construct
from cdk_constructs.eks.eks_cluster import EksCluster
from cdk_constructs.karpenter_sqs_queue import KarpenterSqsQueue
from config.base_config import InfrastructureConfig
from typing import List


class EksBackendStack(Stack):
    """
    EKS Backend Stack for GitOps Architecture.

    Creates a minimal EKS cluster with IAM roles for future GitOps services.
    All addons and workloads will be managed via ArgoCD in a separate repository.
    """

    def __init__(self, scope: Construct, construct_id: str,
                 vpc: ec2.Vpc,
                 public_subnets: ec2.SubnetSelection,
                 eks_private_nat_subnets: ec2.SubnetSelection,
                 eks_workload_sg: ec2.SecurityGroup,
                 eks_main_api_sg: ec2.SecurityGroup,
                 alb_security_group: ec2.SecurityGroup,
                 eks_cluster_additional_sg: ec2.SecurityGroup,
                 db_endpoint: str,
                 db_secret_arn: str,
                 config: InfrastructureConfig,
                 **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        self.config = config

        # TODO: create alb and target if needed for kubernetes ingress.

        self.cluster = EksCluster(
            self,
            "EksCluster",
            vpc=vpc,
            public_subnets=public_subnets,
            eks_private_nat_subnets=eks_private_nat_subnets,
            eks_workload_sg=eks_workload_sg,
            eks_main_api_sg=eks_main_api_sg,
            alb_security_group=alb_security_group,
            eks_cluster_additional_sg=eks_cluster_additional_sg,
            db_endpoint=db_endpoint,
            db_secret_arn=db_secret_arn,
            config=config,
        )

        self.karpenter_sqs_queue = KarpenterSqsQueue(
            self,
            "KarpenterSqsQueue",
            cluster_name=self.cluster.cluster_name,
            config=config,
        )

        self.eks_cluster = self.cluster.eks_cluster
        self.karpenter_node_role = self.cluster.karpenter_node_role
        self.node_role = self.cluster.node_role

        self.config.add_stack_global_tags(self)
