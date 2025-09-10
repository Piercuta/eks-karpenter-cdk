from aws_cdk import Duration
from aws_cdk import aws_ec2 as ec2
from aws_cdk import aws_rds as rds
from aws_cdk import aws_secretsmanager as secretsmanager
from aws_cdk import aws_lambda as lambda_
from aws_cdk import aws_iam as iam
from aws_cdk import aws_kms as kms
from aws_cdk import CustomResource
from aws_cdk import BundlingOptions
from aws_cdk import aws_logs as logs
from constructs import Construct
from typing import List
from config.base_config import InfrastructureConfig
from aws_cdk import RemovalPolicy
import os
from aws_cdk import CfnOutput


class AuroraCluster(Construct):
    def __init__(self, scope: Construct, id: str,
                 vpc: ec2.Vpc,
                 security_group: ec2.SecurityGroup,
                 subnets: List[ec2.ISubnet],
                 rds_lambda_security_group: ec2.SecurityGroup,
                 rds_lambda_subnets: List[ec2.ISubnet],
                 config: InfrastructureConfig,
                 **kwargs) -> None:
        super().__init__(scope, id)
        self.vpc = vpc
        self.security_group = security_group
        self.subnets = subnets
        self.rds_lambda_security_group = rds_lambda_security_group
        self.rds_lambda_subnets = rds_lambda_subnets
        self.config = config
        self.cluster = self._create_cluster()

    def _create_manage_master_user_password_lambda(self, cluster: rds.DatabaseCluster) -> lambda_.Function:
        """
        Create Lambda function to manage master user password.

        Args:
            cluster: The Aurora cluster to manage

        Returns:
            The created Lambda function
        """
        # Create Lambda role
        lambda_role = iam.Role(
            self, "ManageMasterUserPasswordLambdaRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaBasicExecutionRole"),
                iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaVPCAccessExecutionRole")
            ]
        )

        # Add necessary permissions for RDS
        lambda_role.add_to_policy(
            iam.PolicyStatement(
                actions=[
                    "rds:ModifyDBCluster",
                    "rds:DescribeDBClusters",
                    "secretsmanager:*",
                    "kms:*",
                ],
                resources=["*"]
            )
        )

        # Create log group for Lambda
        lambda_log_group = logs.LogGroup(
            self, "ManageMasterUserPasswordLambdaLogGroup",
            log_group_name=f"/{
                self.config.project_name}/{
                self.config.env_name_str}/lambda/{
                self.config.prefix('manage-master-user-password')}",
            retention=logs.RetentionDays.ONE_MONTH,
            removal_policy=RemovalPolicy.DESTROY
        )

        # Create Lambda function
        return lambda_.Function(
            self, "ManageMasterUserPasswordLambda",
            function_name=self.config.prefix("manage-master-user-password"),
            runtime=lambda_.Runtime.PYTHON_3_11,
            handler="manage_master_user_password.handler",
            code=lambda_.Code.from_asset(
                "assets/lambdas/aurora_cluster_lambda",
                bundling=BundlingOptions(
                    image=lambda_.Runtime.PYTHON_3_11.bundling_image,
                    command=[
                        "bash", "-c",
                        "pip install -r requirements.txt -t /asset-output && cp -r . /asset-output"
                    ]
                )
            ),
            role=lambda_role,
            vpc=self.vpc,
            vpc_subnets=self.rds_lambda_subnets,
            security_groups=[self.rds_lambda_security_group],
            timeout=Duration.minutes(5),
            log_group=lambda_log_group
        )

    def _create_cluster(self) -> rds.DatabaseCluster:
        """
        Create the Aurora PostgreSQL cluster with the specified configuration.
        If a snapshot_identifier is provided, the cluster will be created from that snapshot.

        Returns:
            Instance of the created cluster Aurora
        """
        subnet_group = rds.SubnetGroup(
            self, "RdsSubnetGroup",
            subnet_group_name=self.config.prefix("aurora-subnet-group"),
            description="Subnet group for RDS in private subnets",
            vpc=self.vpc,
            vpc_subnets=self.subnets,
            removal_policy=RemovalPolicy.DESTROY
        )
        # Basic cluster configuration
        cluster_config = {
            "cluster_identifier": self.config.prefix("aurora-cluster"),
            "engine": rds.DatabaseClusterEngine.aurora_postgres(
                version=rds.AuroraPostgresEngineVersion.VER_15_3
            ),
            "writer": rds.ClusterInstance.serverless_v2(
                "Writer",
                instance_identifier=self.config.prefix("aurora-writer-instance")
            ),
            "serverless_v2_min_capacity": self.config.database.serverless_v2_min_capacity,
            "serverless_v2_max_capacity": self.config.database.serverless_v2_max_capacity,
            "backup": rds.BackupProps(
                retention=Duration.days(self.config.database.backup_retention)
            ),
            "enable_performance_insights": True,
            "monitoring_interval": Duration.seconds(60),
            "parameter_group": rds.ParameterGroup.from_parameter_group_name(
                self, "ParameterGroup",
                parameter_group_name="default.aurora-postgresql15"
            ),
            "storage_encrypted": True,
            "vpc": self.vpc,
            "security_groups": [self.security_group],
            "subnet_group": subnet_group,
            "removal_policy": RemovalPolicy.SNAPSHOT if self.config.database.snapshot_on_deletion else RemovalPolicy.DESTROY
        }

        if self.config.database.instance_reader:
            cluster_config["readers"] = [
                rds.ClusterInstance.serverless_v2(
                    "reader",
                    instance_identifier=self.config.prefix("aurora-reader-instance"),
                    scale_with_writer=True
                )
            ]
        # If a snapshot is specified, use it for creation
        if self.config.database.snapshot_identifier:
            cluster_config["snapshot_identifier"] = self.config.database.snapshot_identifier
            cluster = rds.DatabaseClusterFromSnapshot(
                self, "Database",
                **cluster_config
            )
        else:
            cluster = rds.DatabaseCluster(
                self, "Database",
                **cluster_config
            )

        # Lambda for activating the manage_master_user_password feature
        # Create Lambda function
        manage_master_user_password_lambda = self._create_manage_master_user_password_lambda(cluster)

        # Create KMS key for Aurora secrets
        aurora_kms_key = kms.Key(
            self, "AuroraSecretKmsKey",
            alias=f"alias/{self.config.prefix('aurora-secrets')}",
            enable_key_rotation=True,
            removal_policy=RemovalPolicy.DESTROY
        )

        # Grant KMS permissions to Lambda
        aurora_kms_key.grant_encrypt_decrypt(manage_master_user_password_lambda.role)

        # Create custom resource
        custom_resource = CustomResource(
            self, "ManageMasterUserPassword",
            service_token=manage_master_user_password_lambda.function_arn,
            properties={
                "ClusterId": cluster.cluster_identifier,
                "KmsKeyId": aurora_kms_key.key_id
            },
            service_timeout=Duration.minutes(10)
        )

        # Add dependency on writer instance
        writer_instance = cluster.node.find_child("Writer")
        custom_resource.node.add_dependency(writer_instance)
        self.secret_arn_output = custom_resource.get_att("SecretArn").to_string()

        return cluster
