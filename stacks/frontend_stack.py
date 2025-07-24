from aws_cdk import Stack, Duration, RemovalPolicy
from aws_cdk import aws_s3 as s3
from aws_cdk import aws_cloudfront as cloudfront
from aws_cdk import aws_cloudfront_origins as origins
from aws_cdk import aws_iam as iam
from aws_cdk import aws_codepipeline as codepipeline
from aws_cdk import aws_codepipeline_actions as codepipeline_actions
from aws_cdk import aws_codebuild as codebuild
from aws_cdk import aws_route53 as route53
from aws_cdk import aws_route53_targets as targets
from constructs import Construct
from cdk_constructs.static_website import StaticWebsite
from config.base_config import InfrastructureConfig


class FrontendStack(Stack):
    def __init__(self,
                 scope: Construct,
                 construct_id: str,
                 config: InfrastructureConfig,
                 **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        self.config = config
        # Create CloudFront distribution
        self.static_website = StaticWebsite(
            self, "FrontendCloudFront",
            config=self.config,
        )

        # Global tags for the stack
        self.config.add_stack_global_tags(self)
