from aws_cdk import Stack
from aws_cdk import aws_route53 as route53
from aws_cdk import aws_route53_targets as targets
from aws_cdk import Duration
from constructs import Construct
from aws_cdk import Tags
from config.base_config import InfrastructureConfig
from aws_cdk import aws_cloudfront as cloudfront
from aws_cdk import CfnOutput
from aws_cdk import aws_ssm as ssm


class DnsStack(Stack):
    def __init__(self,
                 scope: Construct,
                 construct_id: str,
                 distribution: cloudfront.IDistribution,
                 config: InfrastructureConfig,
                 **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        self.config = config
        self.distribution = distribution
        self.hosted_zone = self._get_hosted_zone()

        self.frontend_dns_record = self._create_frontenddns_records()
        self.media_storage_dns_record = self._create_media_storage_dns_records()
        # Global tags for the stack
        self.config.add_stack_global_tags(self)

        CfnOutput(
            self, "FrontendDomainName",
            value=self.frontend_dns_record.domain_name,
            description="Nom de domaine du frontend",
            export_name="FrontendDomainName"
        )

        CfnOutput(
            self, "FastApiDomainName",
            value=self.config.dns.fastapi_domain_name,
            description="Nom de domaine du fastapi",
            export_name="FastApiDomainName"
        )

        CfnOutput(
            self, "ArgocdDomainName",
            value=f"{self.config.env_name_str}-argocd.piercuta.com",
            description="Nom de domaine du argocd",
            export_name="ArgocdDomainName"
        )

        CfnOutput(
            self, "MediaDomainName",
            value=self.media_storage_dns_record.domain_name,
            description="Nom de domaine du media storage",
            export_name="MediaDomainName"
        )

    def _get_hosted_zone(self):
        # Create Route53 zone
        hosted_zone = route53.HostedZone.from_hosted_zone_attributes(
            self, "HostedZone",
            hosted_zone_id=self.config.dns.hosted_zone_id,
            zone_name=self.config.dns.zone_name
        )

        return hosted_zone

    def _create_frontenddns_records(self):
        # Create A record for the frontend domain (CloudFront)
        return route53.ARecord(
            self, "FrontendDnsRecord",
            zone=self.hosted_zone,
            record_name=self.config.dns.frontend_domain_name,
            target=route53.RecordTarget.from_alias(
                targets.CloudFrontTarget(self.distribution)
            ),
            ttl=Duration.minutes(5)
        )

    def _create_media_storage_dns_records(self):
        # Create A record for the media storage domain (CloudFront)
        return route53.ARecord(
            self, "MediaStorageDnsRecord",
            zone=self.hosted_zone,
            record_name=self.config.dns.media_domain_name,
            target=route53.RecordTarget.from_alias(
                targets.CloudFrontTarget(self.distribution)
            ),
            ttl=Duration.minutes(5)
        )
