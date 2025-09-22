from aws_cdk import Stack, RemovalPolicy, Duration
from aws_cdk import aws_codebuild as codebuild
from aws_cdk import aws_codepipeline as codepipeline
from aws_cdk import aws_codepipeline_actions as codepipeline_actions
from aws_cdk import aws_iam as iam
from aws_cdk import aws_s3 as s3
from aws_cdk import aws_s3_assets as s3_assets
from aws_cdk import aws_logs as logs
from aws_cdk import aws_eks as eks
from aws_cdk import aws_secretsmanager as secretsmanager
from aws_cdk import CustomResource
from aws_cdk import aws_lambda as lambda_
from aws_cdk import BundlingOptions
from aws_cdk import aws_ec2 as ec2
from config.base_config import InfrastructureConfig
from constructs import Construct


class CICDK8sDeployStack(Stack):
    """
    CI/CD Stack for Kubernetes deployment with ArgoCD.

    Creates a complete pipeline that:
    1. Sources code from a Git repository
    2. Builds and deploys Kubernetes manifests
    3. Installs and configures ArgoCD
    4. Deploys applications via ArgoCD
    """

    def __init__(self,
                 scope: Construct,
                 construct_id: str,
                 config: InfrastructureConfig,
                 eks_cluster_name: str,
                 vpc_id: str,
                 karpenter_node_role: iam.Role,
                 eks_node_role: iam.Role,
                 alb_sg: ec2.SecurityGroup,
                 **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        self.config = config
        self.eks_cluster_name = eks_cluster_name
        self.karpenter_node_role = karpenter_node_role
        self.eks_node_role = eks_node_role
        self.alb_sg = alb_sg
        self.vpc_id = vpc_id
        self.k8s_codebuild_role, self.k8s_codebuild_access_entry, self.k8s_codebuild_policy = self._create_codebuild_role_and_access_entry()
        self._create_k8s_deploy_pipeline()
        self._create_cleanup_custom_resource()
        self.config.add_stack_global_tags(self)

    def _create_k8s_deploy_pipeline(self):
        """Create the complete Kubernetes deployment pipeline with ArgoCD."""

        pipeline_assets = s3_assets.Asset(self, "K8sDeployPipelineAssets", path="./assets/pipelines/k8s_deploy")

        artifact_bucket = s3.Bucket(self, "K8sDeployPipelineArtifacts",
                                    bucket_name=self.config.prefix("k8s-deploy-pipeline-artifacts"),
                                    removal_policy=RemovalPolicy.DESTROY,
                                    auto_delete_objects=True)

        # IAM Role pour CodeBuild (à restreindre en prod)
        # codebuild_role = self._create_codebuild_role()

        # Log group
        log_group = logs.LogGroup(self, "K8sDeployPipelineLogs",
                                  removal_policy=RemovalPolicy.DESTROY)

        # Projet CodeBuild (le même que dans ton exemple précédent)
        build_project = codebuild.Project(
            self, "K8sDeployCodeBuildProject",
            project_name=self.config.prefix("k8s-deploy-codebuild-project"),
            environment=codebuild.BuildEnvironment(
                build_image=codebuild.LinuxBuildImage.STANDARD_7_0,
                privileged=True,
                environment_variables={
                    "CLUSTER_NAME": codebuild.BuildEnvironmentVariable(value=self.eks_cluster_name),
                    "VPC_ID": codebuild.BuildEnvironmentVariable(value=self.vpc_id),
                    "AWS_REGION": codebuild.BuildEnvironmentVariable(value=self.config.aws.region_str),
                    "PROJECT_NAME": codebuild.BuildEnvironmentVariable(value=self.config.project_name),
                    "ENV_NAME": codebuild.BuildEnvironmentVariable(value=self.config.env_name_str),
                    "ACCOUNT_ID": codebuild.BuildEnvironmentVariable(value=self.config.aws.account),
                    "KARPENTER_NODE_ROLE": codebuild.BuildEnvironmentVariable(value=self.karpenter_node_role.role_name),
                    "EKS_NODE_ROLE": codebuild.BuildEnvironmentVariable(value=self.eks_node_role.role_name),
                    "CERTIFICATE_ARN": codebuild.BuildEnvironmentVariable(value=self.config.cicd_k8s_fastapi.certificate_arn),
                    "ARGOCD_DOMAIN_NAME": codebuild.BuildEnvironmentVariable(value=self.config.dns.argocd_domain_name),
                    "ALB_SG_ID": codebuild.BuildEnvironmentVariable(value=self.alb_sg.security_group_id),
                },
            ),
            source=codebuild.Source.s3(bucket=pipeline_assets.bucket, path=pipeline_assets.s3_object_key),
            build_spec=codebuild.BuildSpec.from_source_filename("buildspec.yaml"),
            timeout=Duration.minutes(30),
            logging=codebuild.LoggingOptions(cloud_watch=codebuild.CloudWatchLoggingOptions(log_group=log_group)),
            role=self.k8s_codebuild_role,
        )

        # Crée la pipeline
        pipeline = codepipeline.Pipeline(
            self, "K8sDeployCodePipeline",
            artifact_bucket=artifact_bucket,
            pipeline_name=self.config.prefix("k8s-deploy-pipeline")
        )

        # Étape Source : simule une source S3 (l'asset)
        source_output = codepipeline.Artifact()
        pipeline.add_stage(
            stage_name="Source",
            actions=[
                codepipeline_actions.S3SourceAction(
                    action_name="SourceFromS3Asset",
                    bucket=pipeline_assets.bucket,
                    bucket_key=pipeline_assets.s3_object_key,
                    output=source_output,
                    trigger=codepipeline_actions.S3Trigger.NONE
                )
            ]
        )

        # Étape Build : exécute ton projet CodeBuild
        pipeline.add_stage(
            stage_name="Build",
            actions=[
                codepipeline_actions.CodeBuildAction(
                    action_name="DeployToK8s",
                    project=build_project,
                    input=source_output
                )
            ]
        )

    def _create_codebuild_role_and_access_entry(self) -> iam.Role:
        """Create IAM role for CodeBuild with necessary permissions."""

        role = iam.Role(
            self, "K8sDeployCodeBuildRole",
            role_name=self.config.prefix("k8s-deploy-codebuild-role"),
            assumed_by=iam.ServicePrincipal("codebuild.amazonaws.com"),
            description="IAM role for Kubernetes deployment CodeBuild project"
        )

        # Add managed policies
        role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("AmazonEKSClusterPolicy")
        )
        role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("AmazonEKSWorkerNodePolicy")
        )
        # role.add_managed_policy(
        #     iam.ManagedPolicy.from_aws_managed_policy_name("AdministratorAccess")
        # )
        # Add custom policies for EKS and deployment operations

        policy = iam.ManagedPolicy(
            self, "K8sDeployCodeBuildPolicy",
            managed_policy_name=self.config.prefix("k8s-deploy-codebuild-policy"),
            statements=[
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=[
                        "eks:DescribeCluster",
                        "eks:ListClusters",
                        "eks:AccessKubernetesApi",
                        "eks:DescribeNodegroup",
                        "eks:ListNodegroups",
                        "ec2:*",
                        "iam:*",
                        "s3:GetObject",
                        "s3:PutObject",
                        "s3:DeleteObject",
                        "s3:ListBucket",
                        "logs:*",
                        "cloudwatch:*",
                        "kms:Decrypt",
                        "kms:GenerateDataKey",
                        "secretsmanager:GetSecretValue",
                        "ssm:GetParameter",
                        "ssm:GetParameters"
                    ],
                    resources=["*"]
                )
            ]
        )

        role.add_managed_policy(policy)

        access_entry = eks.CfnAccessEntry(
            self, "AccessEntry1",
            cluster_name=self.eks_cluster_name,
            principal_arn=role.role_arn,
            access_policies=[
                eks.CfnAccessEntry.AccessPolicyProperty(
                    access_scope=eks.CfnAccessEntry.AccessScopeProperty(
                        type="cluster"
                    ),
                    policy_arn="arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
                )
            ],
            type="STANDARD"
        )

        return role, access_entry, policy

    def _create_cleanup_custom_resource(self):
        """Create a Custom Resource that triggers cleanup of ingress resources on stack deletion."""

        # Create Lambda function for cleanup
        cleanup_lambda = self._create_cleanup_lambda()

        # Create Custom Resource that triggers on deletion
        cleanup_custom_resource = CustomResource(
            self, "IngressCleanupResource",
            service_token=cleanup_lambda.function_arn,
            properties={
                "ProjectName": self.config.project_name,
                "Environment": self.config.env_name_str,
            },
            service_timeout=Duration.minutes(10)
        )

        # Add dependency to ensure Lambda is created before Custom Resource
        cleanup_custom_resource.node.add_dependency(self.k8s_codebuild_access_entry)
        cleanup_custom_resource.node.add_dependency(self.k8s_codebuild_policy)

        return cleanup_custom_resource

    def _create_cleanup_codebuild_project(self):
        """Create CodeBuild project for EKS cleanup, using buildspec.cleanup.yaml in assets/ folder."""

        # Asset for the buildspec file
        cleanup_buildspec_asset = s3_assets.Asset(
            self, "CleanupBuildspecAsset", path="assets/pipelines/k8s_deploy")

        log_group = logs.LogGroup(self, "CleanupCodeBuildLogGroup",
                                  log_group_name=f"/aws/codebuild/{
                                      self.config.prefix('eks-cleanup-codebuild-project')}",
                                  retention=logs.RetentionDays.ONE_WEEK,
                                  removal_policy=RemovalPolicy.DESTROY)

        cleanup_project = codebuild.Project(
            self, "CleanupEksCodeBuildProject",
            project_name=self.config.prefix("eks-cleanup-codebuild-project"),
            environment=codebuild.BuildEnvironment(
                build_image=codebuild.LinuxBuildImage.STANDARD_7_0,
                privileged=True,
                environment_variables={
                    "CLUSTER_NAME": codebuild.BuildEnvironmentVariable(value=self.eks_cluster_name),
                    "EKS_REGION": codebuild.BuildEnvironmentVariable(value=self.config.aws.region_str),
                    "ENVIRONMENT": codebuild.BuildEnvironmentVariable(value=self.config.env_name_str),
                    "KARPENTER_NODE_ROLE": codebuild.BuildEnvironmentVariable(value=self.karpenter_node_role.role_name),
                },
            ),
            source=codebuild.Source.s3(
                bucket=cleanup_buildspec_asset.bucket,
                path=cleanup_buildspec_asset.s3_object_key),
            build_spec=codebuild.BuildSpec.from_source_filename("buildspec.cleanup.yaml"),
            timeout=Duration.minutes(10),
            logging=codebuild.LoggingOptions(cloud_watch=codebuild.CloudWatchLoggingOptions(log_group=log_group)),
            role=self.k8s_codebuild_role,
        )
        return cleanup_project

    def _create_cleanup_lambda(self):
        """Create Lambda function that will be triggered during stack deletion to clean up ingress resources."""

        # Create IAM role for Lambda
        lambda_role = iam.Role(
            self, "CleanupLambdaRole",
            role_name=self.config.prefix("cleanup-lambda-role"),
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            description="IAM role for cleanup Lambda function"
        )

        # Add basic Lambda execution permissions
        lambda_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaBasicExecutionRole")
        )

        # Create the actual Lambda function using CDK
        cleanup_codebuild_project = self._create_cleanup_codebuild_project()

        # Add permissions
        lambda_role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=[
                "codebuild:*",
                "ec2:*",
            ],
            resources=[
                cleanup_codebuild_project.project_arn,
                "*"
            ]
        ))

        cleanup_function = lambda_.Function(
            self, "CleanupFunction",
            function_name=self.config.prefix("cleanup-lambda"),
            runtime=lambda_.Runtime.PYTHON_3_10,
            handler="cleanup_eks_cluster.handler",
            code=lambda_.Code.from_asset(
                "assets/lambdas/cleanup_eks",
                bundling=BundlingOptions(
                    image=lambda_.Runtime.PYTHON_3_11.bundling_image,
                    command=[
                        "bash", "-c",
                        "pip install -r requirements.txt -t /asset-output && cp -r . /asset-output"
                    ]
                )
            ),
            role=lambda_role,
            timeout=Duration.minutes(10),
            memory_size=512,
            environment={
                "CLUSTER_NAME": self.eks_cluster_name,
                "EKS_REGION": self.config.aws.region_str,
                "CODEBUILD_PROJECT_NAME": cleanup_codebuild_project.project_name
            }
        )
        return cleanup_function
