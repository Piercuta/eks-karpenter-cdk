from aws_cdk import Stack, RemovalPolicy
from aws_cdk import aws_codebuild as codebuild
from aws_cdk import aws_codepipeline as codepipeline
from aws_cdk import aws_codepipeline_actions as codepipeline_actions
from aws_cdk import aws_iam as iam
from aws_cdk import aws_ecr as ecr
from aws_cdk import aws_s3 as s3
from aws_cdk import aws_logs as logs
from config.base_config import InfrastructureConfig
from constructs import Construct
from aws_cdk import aws_eks as eks
from cdk_constructs.eks.eks_utils import create_standard_admin_access_entry, create_pod_identity_association
from aws_cdk import aws_s3_assets as s3_assets
from aws_cdk import Duration
from aws_cdk import aws_elasticloadbalancingv2 as elbv2
from aws_cdk import aws_ec2 as ec2


class CICDK8sMainAPIStack(Stack):
    def __init__(self,
                 scope: Construct,
                 construct_id: str,
                 eks_cluster: eks.CfnCluster,
                 db_endpoint: str,
                 db_secret_arn: str,
                 eks_main_api_sg: ec2.SecurityGroup,
                 alb_sg: ec2.SecurityGroup,
                 karpenter_node_role: iam.Role,
                 config: InfrastructureConfig,
                 **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        self.config = config
        self.eks_cluster = eks_cluster
        self.karpenter_node_role = karpenter_node_role
        self.main_api_codebuild_role = self._create_main_api_codebuild_role_and_access_entry()
        self.main_api_service_account_role = self._create_main_api_service_account_role()
        self.db_endpoint = db_endpoint
        self.db_secret_arn = db_secret_arn
        self.eks_main_api_sg = eks_main_api_sg
        self.alb_sg = alb_sg
        self._create_main_api_pipeline()
        self._create_main_api_gitops_env_pipeline()
        self.config.add_stack_global_tags(self)

    def _create_main_api_codebuild_role_and_access_entry(self) -> iam.Role:
        """Create IAM role for MainAPI CodeBuild."""
        role = iam.Role(
            self, "MainApiCodeBuildRole",
            role_name=self.config.prefix("main-api-codebuild-role"),
            assumed_by=iam.ServicePrincipal("codebuild.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("AWSCodeBuildDeveloperAccess"),
            ],
            description="IAM role for MainAPI CodeBuild service",
        )

        # Add EKS and ECR permissions
        role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=[
                "eks:*",
                "ecr:*",
                "logs:*",
                "cloudwatch:*",
                "s3:*",
                "iam:GetRole",
                "iam:ListRoles",
                "iam:PassRole",
                "kms:*",
                "ssm:*",
                # secretsmanager is needed to get the GitHub token
                "secretsmanager:*"
            ],
            resources=["*"]
        ))

        create_standard_admin_access_entry(
            scope=self,
            id="AccessEntryMainApi",
            cluster_name=self.eks_cluster.name,
            principal_arn=role.role_arn,
        )

        return role

    def _create_main_api_service_account_role(self) -> iam.Role:
        trust_policy = iam.PolicyDocument(
            statements=[
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    principals=[
                        iam.ServicePrincipal("pods.eks.amazonaws.com")
                    ],
                    actions=[
                        "sts:AssumeRole",
                        "sts:TagSession"
                    ]
                )
            ]
        )

        role = iam.CfnRole(
            self, "MainApiServiceAccountRole",
            role_name=self.config.prefix("main-api-serviceaccount-role"),
            assume_role_policy_document=trust_policy,
            description="IAM role for MainAPI service account",
            policies=[
                iam.CfnRole.PolicyProperty(
                    policy_name="MainApiServiceAccountPolicy",
                    policy_document=iam.PolicyDocument(
                        statements=[
                            iam.PolicyStatement(
                                effect=iam.Effect.ALLOW,
                                actions=["rds:*", "secretsmanager:*", "ecr:*", "kms:*"],
                                resources=["*"]
                            )
                        ]
                    )
                )
            ]
        )

        create_pod_identity_association(
            scope=self,
            id="MainApiServiceAccount",
            cluster_name=self.eks_cluster.name,
            namespace=f"main-api-{self.config.env_name_str}",
            service_account="main-api",
            role_arn=role.get_att("Arn").to_string(),
            pod_identity_agent_dependency=role
        )

        return role

    def _create_main_api_pipeline(self):
        """Create a simple pipeline that builds and pushes Docker image to ECR."""

        # Import existing ECR repository
        ecr_repo = ecr.Repository.from_repository_name(
            self, "MainApiEcrRepo",
            repository_name=self.config.cicd_k8s_main_api.ecr_repository_name
        )

        # Create S3 bucket for pipeline artifacts
        artifact_bucket = s3.Bucket(
            self, "PipelineArtifactBucket",
            bucket_name=f"{self.config.prefix('pipeline-artifacts-main-api')}",
            removal_policy=RemovalPolicy.DESTROY,
            auto_delete_objects=True,
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL
        )

        # Create source artifact
        source_output = codepipeline.Artifact()

        # Create pipeline
        pipeline = codepipeline.Pipeline(
            self, "MainApiPipeline",
            pipeline_name=self.config.prefix("main-api-pipeline"),
            artifact_bucket=artifact_bucket,
            cross_account_keys=False
        )

        # Add source stage
        pipeline.add_stage(
            stage_name="Source",
            actions=[
                codepipeline_actions.CodeStarConnectionsSourceAction(
                    action_name="GitHubSource",
                    owner=self.config.cicd_k8s_main_api.github.owner,
                    repo=self.config.cicd_k8s_main_api.github.repo,
                    branch=self.config.cicd_k8s_main_api.github.branch,
                    connection_arn=self.config.cicd_k8s_main_api.github.connection_arn,
                    output=source_output,
                    code_build_clone_output=True
                )
            ]
        )

        # Add build stage
        pipeline.add_stage(
            stage_name="Build",
            actions=[
                codepipeline_actions.CodeBuildAction(
                    action_name="BuildAndPush",
                    input=source_output,
                    project=codebuild.PipelineProject(
                        self, "BackendBuildProject",
                        project_name=self.config.prefix("backend-build"),
                        role=self.main_api_codebuild_role,
                        environment=codebuild.BuildEnvironment(
                            build_image=codebuild.LinuxBuildImage.STANDARD_7_0,
                            privileged=True,
                            compute_type=codebuild.ComputeType.SMALL
                        ),
                        environment_variables={
                            "AWS_DEFAULT_REGION": codebuild.BuildEnvironmentVariable(
                                value=self.config.aws.region_str
                            ),
                            "AWS_ACCOUNT_ID": codebuild.BuildEnvironmentVariable(
                                value=self.config.aws.account
                            ),
                            "IMAGE_REPO_NAME": codebuild.BuildEnvironmentVariable(
                                value=ecr_repo.repository_name
                            ),
                            "IMAGE_TAG": codebuild.BuildEnvironmentVariable(
                                value=self.config.cicd_k8s_main_api.ecr_image_tag
                            ),
                            "ECR_REPOSITORY_URI": codebuild.BuildEnvironmentVariable(
                                value=ecr_repo.repository_uri
                            ),
                            "BRANCH_NAME": codebuild.BuildEnvironmentVariable(
                                value=self.config.cicd_k8s_main_api.github.branch
                            )
                        },
                        build_spec=codebuild.BuildSpec.from_source_filename("buildspec.yml"),
                        logging=codebuild.LoggingOptions(
                            cloud_watch=codebuild.CloudWatchLoggingOptions(
                                log_group=logs.LogGroup(
                                    self, "BackendBuildLogGroup",
                                    log_group_name=f"/aws/codebuild/{self.config.prefix('backend-build')}",
                                    removal_policy=RemovalPolicy.DESTROY,
                                    retention=logs.RetentionDays.ONE_MONTH
                                )
                            )
                        )
                    )
                )
            ]
        )

        # Grant ECR permissions to the CodeBuild role
        ecr_repo.grant_pull_push(self.main_api_codebuild_role)

        # Add permissions for ECR login
        self.main_api_codebuild_role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=[
                "ecr:GetAuthorizationToken",
                "ecr:BatchCheckLayerAvailability",
                "ecr:GetDownloadUrlForLayer",
                "ecr:BatchGetImage"
            ],
            resources=["*"]
        ))

    def _create_main_api_gitops_env_pipeline(self):
        """Create the complete Kubernetes deployment pipeline with ArgoCD."""

        pipeline_assets = s3_assets.Asset(self, "MainApiGitOpsEnvPipelineAssets",
                                          path="./assets/pipelines/k8s_main_api")

        artifact_bucket = s3.Bucket(self, "MainApiGitOpsEnvPipelineArtifacts",
                                    bucket_name=self.config.prefix("main-api-gitops-env-pipeline-artifacts"),
                                    removal_policy=RemovalPolicy.DESTROY,
                                    auto_delete_objects=True)

        # Log group
        log_group = logs.LogGroup(self, "MainApiGitOpsEnvPipelineLogs",
                                  removal_policy=RemovalPolicy.DESTROY)

        # Projet CodeBuild (le même que dans ton exemple précédent)
        build_project = codebuild.Project(
            self, "MainApiGitOpsEnvCodeBuildProject",
            project_name=self.config.prefix("main-api-gitops-env-codebuild-project"),
            environment=codebuild.BuildEnvironment(
                build_image=codebuild.LinuxBuildImage.STANDARD_7_0,
                privileged=True,
                environment_variables={
                    "AWS_REGION": codebuild.BuildEnvironmentVariable(value=self.config.aws.region_str),
                    "DOMAIN_NAME": codebuild.BuildEnvironmentVariable(value=self.config.dns.main_api_domain_name),
                    "ENV_NAME": codebuild.BuildEnvironmentVariable(value=self.config.env_name_str),
                    "CLUSTER_NAME": codebuild.BuildEnvironmentVariable(value=self.eks_cluster.name),
                    "PROJECT_NAME": codebuild.BuildEnvironmentVariable(value=self.config.project_name),
                    "POSTGRES_SERVER": codebuild.BuildEnvironmentVariable(value=self.db_endpoint),
                    "FRONTEND_HOST": codebuild.BuildEnvironmentVariable(value='https://' + self.config.frontend.domain_name),
                    "AWS_SECRET_ARN": codebuild.BuildEnvironmentVariable(value=self.db_secret_arn),
                    "CERTIFICATE_ARN": codebuild.BuildEnvironmentVariable(value=self.config.cicd_k8s_main_api.certificate_arn),
                    "IMAGE_URL": codebuild.BuildEnvironmentVariable(
                        value=f'{self.config.aws.account}.dkr.ecr.{self.config.aws.region_str}.amazonaws.com/{self.config.cicd_k8s_main_api.ecr_repository_name}'),
                    "TAG": codebuild.BuildEnvironmentVariable(value=self.config.cicd_k8s_main_api.ecr_image_tag),
                    # kubernetes local url for file service
                    "CPU_CAPACITY": codebuild.BuildEnvironmentVariable(value=self.config.cicd_k8s_main_api.cpu_capacity),
                    "MEM_CAPACITY": codebuild.BuildEnvironmentVariable(value=self.config.cicd_k8s_main_api.mem_capacity),
                    "DESIRED_REPLICAS": codebuild.BuildEnvironmentVariable(value=self.config.cicd_k8s_main_api.replicas),
                    "MIN_REPLICAS": codebuild.BuildEnvironmentVariable(value=self.config.cicd_k8s_main_api.min_replicas),
                    "MAX_REPLICAS": codebuild.BuildEnvironmentVariable(value=self.config.cicd_k8s_main_api.max_replicas),
                    "SG_MAIN_API": codebuild.BuildEnvironmentVariable(value=self.eks_main_api_sg.security_group_id),

                    "MAIN_API_DOMAIN_NAME": codebuild.BuildEnvironmentVariable(value=self.config.dns.main_api_domain_name),
                    "ALB_SG_ID": codebuild.BuildEnvironmentVariable(value=self.alb_sg.security_group_id),
                },
            ),
            source=codebuild.Source.s3(bucket=pipeline_assets.bucket, path=pipeline_assets.s3_object_key),
            build_spec=codebuild.BuildSpec.from_source_filename("buildspec.yaml"),
            timeout=Duration.minutes(30),
            logging=codebuild.LoggingOptions(cloud_watch=codebuild.CloudWatchLoggingOptions(log_group=log_group)),
            role=self.main_api_codebuild_role,
        )

        # Crée la pipeline
        pipeline = codepipeline.Pipeline(
            self, "MainApiGitOpsEnvCodePipeline",
            artifact_bucket=artifact_bucket,
            pipeline_name=self.config.prefix("main-api-gitops-env-pipeline")
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
                    action_name="GitOpsEnv",
                    project=build_project,
                    input=source_output
                )
            ]
        )
