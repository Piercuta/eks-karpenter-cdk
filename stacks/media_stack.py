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
from cdk_constructs.media_distribution import MediaDistribution
from config.base_config import InfrastructureConfig


class MediaStack(Stack):
    def __init__(self,
                 scope: Construct,
                 construct_id: str,
                 config: InfrastructureConfig,
                 **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        self.config = config
        # Create CloudFront distribution
        self.media_distribution = MediaDistribution(
            self, "MediaCloudFront",
            config=self.config,
        )
        self.bucket_distribution = self.media_distribution.bucket
        self.distribution_domain_name = self.media_distribution.distribution.domain_name
        # Global tags for the stack
        self.config.add_stack_global_tags(self)
