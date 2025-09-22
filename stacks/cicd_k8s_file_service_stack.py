from aws_cdk import Stack
from constructs import Construct
from aws_cdk import aws_eks as eks
from aws_cdk import aws_ec2 as ec2
from aws_cdk import aws_iam as iam
from aws_cdk import aws_ecr as ecr
from aws_cdk import aws_s3 as s3
from aws_cdk import aws_logs as logs
from aws_cdk import aws_codebuild as codebuild
from aws_cdk import aws_codepipeline as codepipeline
from aws_cdk import aws_codepipeline_actions as codepipeline_actions
from aws_cdk import aws_s3_assets as s3_assets
from aws_cdk import Duration
from aws_cdk import RemovalPolicy
from cdk_constructs.eks.eks_utils import create_standard_admin_access_entry, create_pod_identity_association
from config.base_config import InfrastructureConfig


class CICDK8sFileServiceStack(Stack):
    def __init__(self,
                 scope: Construct,
                 construct_id: str,
                 eks_cluster: eks.CfnCluster,
                 eks_workload_sg: ec2.SecurityGroup,
                 bucket_distribution_name: str,
                 config: InfrastructureConfig,
                 **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        self.config = config
        self.eks_cluster = eks_cluster
        self.file_service_codebuild_role = self._create_file_service_codebuild_role_and_access_entry()
        self.file_service_service_account_role = self._create_file_service_service_account_role()
        self.eks_workload_sg = eks_workload_sg
        self.bucket_distribution_name = bucket_distribution_name
        self._create_file_service_pipeline()
        self._create_file_service_gitops_env_pipeline()
        self.config.add_stack_global_tags(self)

    def _create_file_service_codebuild_role_and_access_entry(self) -> iam.Role:
        """Create IAM role for File Service CodeBuild."""
        role = iam.Role(
            self, "FileServiceCodeBuildRole",
            role_name=self.config.prefix("file-service-codebuild-role"),
            assumed_by=iam.ServicePrincipal("codebuild.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("AWSCodeBuildDeveloperAccess"),
            ],
            description="IAM role for File Service CodeBuild service",
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
            id="AccessEntryFileService",
            cluster_name=self.eks_cluster.name,
            principal_arn=role.role_arn,
        )

        return role

    def _create_file_service_service_account_role(self) -> iam.Role:
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
            self, "FileServiceServiceAccountRole",
            role_name=self.config.prefix("file-service-serviceaccount-role"),
            assume_role_policy_document=trust_policy,
            description="IAM role for File Service service account",
            policies=[
                iam.CfnRole.PolicyProperty(
                    policy_name="FileServiceServiceAccountPolicy",
                    policy_document=iam.PolicyDocument(
                        statements=[
                            iam.PolicyStatement(
                                effect=iam.Effect.ALLOW,
                                actions=[
                                    "s3:*",
                                    "cloudfront:*",
                                    "kms:*"
                                ],
                                resources=["*"]
                            )
                        ]
                    )
                )
            ]
        )

        create_pod_identity_association(
            scope=self,
            id="FileServiceServiceAccount",
            cluster_name=self.eks_cluster.name,
            namespace=f"media-api-{self.config.env_name_str}",
            service_account="media-api",
            role_arn=role.get_att("Arn").to_string(),
            pod_identity_agent_dependency=role
        )

        return role

    def _create_file_service_pipeline(self):
        """Create File Service pipeline."""
        # Import existing ECR repository
        ecr_repo = ecr.Repository.from_repository_name(
            self, "FileServiceEcrRepo",
            repository_name=self.config.cicd_k8s_file_service.ecr_repository_name
        )

        # Create S3 bucket for pipeline artifacts
        artifact_bucket = s3.Bucket(
            self, "PipelineArtifactBucket",
            bucket_name=f"{self.config.prefix('pipeline-artifacts-file-service')}",
            removal_policy=RemovalPolicy.DESTROY,
            auto_delete_objects=True,
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL
        )

        # Create source artifact
        source_output = codepipeline.Artifact()

        # Create pipeline
        pipeline = codepipeline.Pipeline(
            self, "FileServicePipeline",
            pipeline_name=self.config.prefix("file-service-pipeline"),
            artifact_bucket=artifact_bucket,
            cross_account_keys=False
        )

        # Add source stage
        pipeline.add_stage(
            stage_name="Source",
            actions=[
                codepipeline_actions.CodeStarConnectionsSourceAction(
                    action_name="GitHubSource",
                    owner=self.config.cicd_k8s_file_service.github.owner,
                    repo=self.config.cicd_k8s_file_service.github.repo,
                    branch=self.config.cicd_k8s_file_service.github.branch,
                    connection_arn=self.config.cicd_k8s_file_service.github.connection_arn,
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
                        project_name=self.config.prefix("file-service-build"),
                        role=self.file_service_codebuild_role,
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
                                value=self.config.cicd_k8s_file_service.ecr_image_tag
                            ),
                            "ECR_REPOSITORY_URI": codebuild.BuildEnvironmentVariable(
                                value=ecr_repo.repository_uri
                            ),
                            "BRANCH_NAME": codebuild.BuildEnvironmentVariable(
                                value=self.config.cicd_k8s_file_service.github.branch
                            )
                        },
                        build_spec=codebuild.BuildSpec.from_source_filename("buildspec.yml"),
                        logging=codebuild.LoggingOptions(
                            cloud_watch=codebuild.CloudWatchLoggingOptions(
                                log_group=logs.LogGroup(
                                    self, "FileServiceBuildLogGroup",
                                    log_group_name=f"/aws/codebuild/{self.config.prefix('file-service-build')}",
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
        ecr_repo.grant_pull_push(self.file_service_codebuild_role)

        # Add permissions for ECR login
        self.file_service_codebuild_role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=[
                "ecr:GetAuthorizationToken",
                "ecr:BatchCheckLayerAvailability",
                "ecr:GetDownloadUrlForLayer",
                "ecr:BatchGetImage"
            ],
            resources=["*"]
        ))

    def _create_file_service_gitops_env_pipeline(self):
        """Create File Service gitops env pipeline."""
        pipeline_assets = s3_assets.Asset(self, "FileServiceGitOpsEnvPipelineAssets",
                                          path="./assets/pipelines/k8s_file_service")

        artifact_bucket = s3.Bucket(self, "FileServiceGitOpsEnvPipelineArtifacts",
                                    bucket_name=self.config.prefix("file-service-gitops-env-pipeline-artifacts"),
                                    removal_policy=RemovalPolicy.DESTROY,
                                    auto_delete_objects=True)

        # Log group
        log_group = logs.LogGroup(self, "FileServiceGitOpsEnvPipelineLogs",
                                  removal_policy=RemovalPolicy.DESTROY)

        # Projet CodeBuild (le même que dans ton exemple précédent)
        build_project = codebuild.Project(
            self, "FileServiceGitOpsEnvCodeBuildProject",
            project_name=self.config.prefix("file-service-gitops-env-codebuild-project"),
            environment=codebuild.BuildEnvironment(
                build_image=codebuild.LinuxBuildImage.STANDARD_7_0,
                privileged=True,
                environment_variables={
                    "AWS_REGION": codebuild.BuildEnvironmentVariable(value=self.config.aws.region_str),
                    "CLOUDFRONT_DOMAIN": codebuild.BuildEnvironmentVariable(value=self.config.dns.media_domain_name),
                    "S3_BUCKET_NAME": codebuild.BuildEnvironmentVariable(value=self.bucket_distribution_name),
                    "ENV_NAME": codebuild.BuildEnvironmentVariable(value=self.config.env_name_str),
                    "CLUSTER_NAME": codebuild.BuildEnvironmentVariable(value=self.eks_cluster.name),
                    "PROJECT_NAME": codebuild.BuildEnvironmentVariable(value=self.config.project_name),
                    "IMAGE_URL": codebuild.BuildEnvironmentVariable(
                        value=f'{self.config.aws.account}.dkr.ecr.{self.config.aws.region_str}.amazonaws.com/{self.config.cicd_k8s_file_service.ecr_repository_name}'),
                    "TAG": codebuild.BuildEnvironmentVariable(value=self.config.cicd_k8s_file_service.ecr_image_tag),
                    "CPU_CAPACITY": codebuild.BuildEnvironmentVariable(value=self.config.cicd_k8s_file_service.cpu_capacity),
                    "MEM_CAPACITY": codebuild.BuildEnvironmentVariable(value=self.config.cicd_k8s_file_service.mem_capacity),
                    "DESIRED_REPLICAS": codebuild.BuildEnvironmentVariable(value=self.config.cicd_k8s_file_service.replicas),
                },
            ),
            source=codebuild.Source.s3(bucket=pipeline_assets.bucket, path=pipeline_assets.s3_object_key),
            build_spec=codebuild.BuildSpec.from_source_filename("buildspec.yaml"),
            timeout=Duration.minutes(30),
            logging=codebuild.LoggingOptions(cloud_watch=codebuild.CloudWatchLoggingOptions(log_group=log_group)),
            role=self.file_service_codebuild_role,
        )

        # Crée la pipeline
        pipeline = codepipeline.Pipeline(
            self, "FileServiceGitOpsEnvCodePipeline",
            artifact_bucket=artifact_bucket,
            pipeline_name=self.config.prefix("file-service-gitops-env-pipeline")
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
