from aws_cdk import Stack, RemovalPolicy
from aws_cdk import aws_codebuild as codebuild
from aws_cdk import aws_codepipeline as codepipeline
from aws_cdk import aws_codepipeline_actions as codepipeline_actions
from aws_cdk import aws_iam as iam
from aws_cdk import aws_s3 as s3
from aws_cdk import aws_logs as logs
from config.base_config import InfrastructureConfig
from constructs import Construct
from cdk_constructs.static_website import StaticWebsite


class CICDFrontendStack(Stack):
    def __init__(self,
                 scope: Construct,
                 construct_id: str,
                 static_website: StaticWebsite,
                 config: InfrastructureConfig,
                 **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        self.config = config
        self.static_website = static_website
        self._create_front_end_pipeline()
        self.config.add_stack_global_tags(self)

    def _create_front_end_pipeline(self):
        # Create S3 buckets for pipeline artifacts
        frontend_artifact_bucket = s3.Bucket(
            self, "FrontendArtifactBucket",
            bucket_name=self.config.prefix("frontend-pipeline-artifacts"),
            removal_policy=RemovalPolicy.DESTROY,
            auto_delete_objects=True,
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL
        )

        # Create log group for frontend build
        frontend_log_group = logs.LogGroup(
            self, "FrontendBuildLogGroup",
            log_group_name=f"/{
                self.config.project_name}/{
                self.config.env_name_str}/codebuild/{
                self.config.prefix('frontend-build')}",
            retention=logs.RetentionDays.ONE_MONTH,
            removal_policy=RemovalPolicy.DESTROY
        )

        # Create CodeBuild project
        build_project = codebuild.PipelineProject(
            self, "FrontendBuild",
            project_name=self.config.prefix("frontend-build"),
            build_spec=codebuild.BuildSpec.from_source_filename("buildspec.yml"),
            environment=codebuild.BuildEnvironment(
                build_image=codebuild.LinuxBuildImage.STANDARD_7_0,
                privileged=True,
                environment_variables={
                    "VITE_API_URL": codebuild.BuildEnvironmentVariable(
                        value="https://" + self.config.dns.fastapi_domain_name
                    ),
                    "BUCKET_NAME": codebuild.BuildEnvironmentVariable(
                        value=self.static_website.bucket.bucket_name
                    ),
                    "DISTRIBUTION_ID": codebuild.BuildEnvironmentVariable(
                        value=self.static_website.distribution.distribution_id
                    )
                }
            ),
            logging=codebuild.LoggingOptions(
                cloud_watch=codebuild.CloudWatchLoggingOptions(
                    log_group=frontend_log_group,
                    prefix=self.config.prefix('frontend-build')
                )
            )
        )

        # Grant permissions to CodeBuild
        self.static_website.bucket.grant_read_write(build_project)

        # Add additional CloudFront permissions
        build_project.add_to_role_policy(
            iam.PolicyStatement(
                actions=["cloudfront:CreateInvalidation"],
                resources=[self.static_website.distribution.distribution_arn]
            )
        )

        # Create Pipeline
        pipeline = codepipeline.Pipeline(
            self, "FrontendPipeline",
            pipeline_name=self.config.prefix("frontend-pipeline"),
            artifact_bucket=frontend_artifact_bucket
        )

        # Source stage
        source_output = codepipeline.Artifact()
        source_action = codepipeline_actions.CodeStarConnectionsSourceAction(
            action_name="GitHub_Source",
            owner=self.config.cicd_frontend.github.owner,
            repo=self.config.cicd_frontend.github.repo,
            branch=self.config.cicd_frontend.github.branch,
            connection_arn=self.config.cicd_frontend.github.connection_arn,
            output=source_output
        )
        pipeline.add_stage(
            stage_name="Source",
            actions=[source_action]
        )

        # Build stage
        build_output = codepipeline.Artifact()
        build_action = codepipeline_actions.CodeBuildAction(
            action_name="Build",
            project=build_project,
            input=source_output,
            outputs=[build_output]
        )
        pipeline.add_stage(
            stage_name="Build",
            actions=[build_action]
        )
