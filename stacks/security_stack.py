from aws_cdk import Stack
from aws_cdk import aws_ec2 as ec2
from constructs import Construct
from aws_cdk import Tags
from config.base_config import InfrastructureConfig


class SecurityStack(Stack):
    def __init__(self,
                 scope: Construct,
                 construct_id: str,
                 vpc: ec2.Vpc,
                 config: InfrastructureConfig,
                 **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        self.config = config

        # Create RDS Security Group
        rds_sg_name = self.config.prefix("rds-sg")
        self.rds_security_group = ec2.SecurityGroup(
            self, "RDSSecurityGroup",
            vpc=vpc,
            description="Security group for RDS instance",
            security_group_name=rds_sg_name
        )
        Tags.of(self.rds_security_group).add("Name", rds_sg_name)

        # Create RDS Lambda Security Group
        rds_lambda_sg_name = self.config.prefix("rds-lambda-sg")
        self.rds_lambda_security_group = ec2.SecurityGroup(
            self, "RDSLambdaSecurityGroup",
            vpc=vpc,
            description="Security group for RDS Lambda",
            security_group_name=rds_lambda_sg_name
        )
        Tags.of(self.rds_lambda_security_group).add("Name", rds_lambda_sg_name)
        # Create ALB Security Group
        alb_sg_name = self.config.prefix("alb-sg")
        self.alb_security_group = ec2.SecurityGroup(
            self, "ALBSecurityGroup",
            vpc=vpc,
            description="Security group for Application Load Balancer",
            security_group_name=alb_sg_name
        )
        Tags.of(self.alb_security_group).add("Name", alb_sg_name)

        # Create EKS Service Security Group(s) for karpenter nodes...
        eks_workload_sg_name = self.config.prefix("eks-workload-sg")
        self.eks_workload_sg = ec2.SecurityGroup(
            self, "EKSWorkloadSecurityGroup",
            vpc=vpc,
            description="Security group for EKS Service",
            security_group_name=eks_workload_sg_name
        )
        Tags.of(self.eks_workload_sg).add("Name", eks_workload_sg_name)

        eks_cluster_additional_sg_name = self.config.prefix("eks-cluster-additional-sg")
        self.eks_cluster_additional_sg = ec2.SecurityGroup(
            self, "EKSClusterAdditionalSecurityGroup",
            vpc=vpc,
            description="Security group for EKS Cluster Additional",
            security_group_name=eks_cluster_additional_sg_name
        )
        Tags.of(self.eks_cluster_additional_sg).add("Name", eks_cluster_additional_sg_name)

        # Create EKS FastAPI Security Group for security group for pods
        eks_fastapi_sg_name = self.config.prefix("eks-fastapi-sg")
        self.eks_fastapi_sg = ec2.SecurityGroup(
            self, "EKSFastAPISecurityGroup",
            vpc=vpc,
            description="Security group for EKS FastAPI",
            security_group_name=eks_fastapi_sg_name
        )
        Tags.of(self.eks_fastapi_sg).add("Name", eks_fastapi_sg_name)

        # Allow all TCP traffic between FastAPI pods
        self.eks_workload_sg.add_ingress_rule(
            peer=self.eks_workload_sg,
            connection=ec2.Port.all_traffic(),
            description="Allow all TCP traffic between FastAPI pods"
        )

        self.eks_fastapi_sg.add_ingress_rule(
            peer=self.eks_fastapi_sg,
            connection=ec2.Port.all_traffic(),
            description="Allow all TCP traffic between FastAPI pods"
        )

        # Allow PostgreSQL access from RDS Lambda
        self.rds_security_group.add_ingress_rule(
            ec2.Peer.security_group_id(self.rds_lambda_security_group.security_group_id),
            ec2.Port.tcp(5432),
            "Allow PostgreSQL access from RDS Lambda"
        )

        # Allow PostgreSQL access from EKS
        # self.rds_security_group.add_ingress_rule(
        #     ec2.Peer.security_group_id(self.eks_workload_sg.security_group_id),
        #     ec2.Port.tcp(5432),
        #     "Allow PostgreSQL access from EKS"
        # )

        self.rds_security_group.add_ingress_rule(
            ec2.Peer.security_group_id(self.eks_fastapi_sg.security_group_id),
            ec2.Port.tcp(5432),
            "Allow PostgreSQL access from EKS"
        )

        # self.eks_workload_sg.add_ingress_rule(
        #     ec2.Peer.security_group_id(self.alb_security_group.security_group_id),
        #     ec2.Port.tcp(8000),
        #     "Allow FastAPI traffic from ALB"
        # )

        self.eks_fastapi_sg.add_ingress_rule(
            ec2.Peer.security_group_id(self.alb_security_group.security_group_id),
            ec2.Port.tcp(8000),
            "Allow FastAPI traffic from ALB"
        )

        # Allow inbound HTTP/HTTPS traffic from anywhere
        self.alb_security_group.add_ingress_rule(
            ec2.Peer.any_ipv4(),
            ec2.Port.tcp(80),
            "Allow HTTP traffic from anywhere"
        )
        self.alb_security_group.add_ingress_rule(
            ec2.Peer.any_ipv4(),
            ec2.Port.tcp(443),
            "Allow HTTPS traffic from anywhere"
        )

        # Global tags for the stack
        self.config.add_stack_global_tags(self)
