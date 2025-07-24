from aws_cdk import Stack
from aws_cdk import aws_ec2 as ec2
from aws_cdk import aws_rds as rds
from aws_cdk import aws_secretsmanager as secretsmanager
from constructs import Construct
from cdk_constructs.aurora_cluster import AuroraCluster
from config.base_config import InfrastructureConfig
from typing import List


class DatabaseStack(Stack):
    def __init__(self,
                 scope: Construct,
                 construct_id: str,
                 vpc: ec2.Vpc,
                 rds_subnets: List[ec2.ISubnet],
                 rds_sg: ec2.SecurityGroup,
                 rds_lambda_sg: ec2.SecurityGroup,
                 rds_lambda_subnets: List[ec2.ISubnet],
                 config: InfrastructureConfig,
                 **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        self.config = config
        # Create Aurora cluster using the construct
        self.aurora = AuroraCluster(
            self, "Aurora",
            vpc=vpc,
            security_group=rds_sg,
            subnets=rds_subnets,
            rds_lambda_security_group=rds_lambda_sg,
            rds_lambda_subnets=rds_lambda_subnets,
            config=config
        )
        self.db_endpoint = self.aurora.cluster.cluster_endpoint.hostname
        self.db_secret_arn = self.aurora.secret_arn_output
        # Global tags for the stack
        self.config.add_stack_global_tags(self)
