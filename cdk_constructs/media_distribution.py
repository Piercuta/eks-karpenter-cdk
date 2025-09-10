from aws_cdk import RemovalPolicy
from aws_cdk import aws_s3 as s3
from aws_cdk import aws_cloudfront as cloudfront
from aws_cdk import aws_cloudfront_origins as origins
from aws_cdk import aws_iam as iam
from aws_cdk import aws_certificatemanager as acm
from aws_cdk import aws_route53 as route53
from aws_cdk import aws_route53_targets as targets
from aws_cdk import Tags
from constructs import Construct
from config.base_config import InfrastructureConfig


class MediaDistribution(Construct):
    def __init__(self, scope: Construct, id: str, config: InfrastructureConfig, **kwargs) -> None:
        super().__init__(scope, id)

        # Create S3 bucket for static website hosting
        self.bucket = s3.Bucket(
            self, "MediaBucket",
            bucket_name=config.prefix("media-bucket"),
            removal_policy=RemovalPolicy.DESTROY,
            auto_delete_objects=True,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            encryption=s3.BucketEncryption.S3_MANAGED
        )

        self.oac = cloudfront.S3OriginAccessControl(
            self, "MyOAC",
            signing=cloudfront.Signing.SIGV4_NO_OVERRIDE
        )

        # 4. Response Headers Policy (CORS)
        cors_policy = cloudfront.ResponseHeadersPolicy(
            self, "CorsPolicy",
            response_headers_policy_name=config.prefix("media-cors-policy"),
            cors_behavior=cloudfront.ResponseHeadersCorsBehavior(
                access_control_allow_credentials=False,
                access_control_allow_headers=["*"],
                access_control_allow_methods=["GET", "HEAD", "OPTIONS"],
                access_control_allow_origins=["*"],
                origin_override=True
            ),
            comment="Allow CORS from any origin for media distribution"
        )

        # Create CloudFront Distribution
        self.distribution = cloudfront.Distribution(
            self, "Distribution",
            comment=config.prefix("media-distribution"),
            default_behavior=cloudfront.BehaviorOptions(
                origin=origins.S3BucketOrigin.with_origin_access_control(
                    self.bucket,
                    origin_access_control=self.oac
                ),
                viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
                cache_policy=cloudfront.CachePolicy.CACHING_OPTIMIZED,
                allowed_methods=cloudfront.AllowedMethods.ALLOW_ALL,
                compress=True,
                response_headers_policy=cors_policy
            ),
            price_class=cloudfront.PriceClass.PRICE_CLASS_100,
            # enable_logging=True,
            # log_includes_cookies=True,
            # domain_names=[config.dns.media_domain_name],
            # certificate=acm.Certificate.from_certificate_arn(
            #     self, "ImportedCert",
            #     config.frontend.certificate_arn
            # )
        )

        # add logs via cloudwatch or athena to see...
        Tags.of(self.distribution).add("Name", config.prefix("media-distribution"))
