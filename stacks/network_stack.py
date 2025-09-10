from aws_cdk import Stack
from constructs import Construct
from cdk_constructs.vpc.automatic_vpc import AutomaticVpc
from aws_cdk import aws_ec2 as ec2
from config.base_config import InfrastructureConfig
from cdk_constructs.vpc.custom_vpc_v2 import CustomVpcV2
from aws_cdk import aws_iam as iam


class NetworkStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, config: InfrastructureConfig, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        self.config = config

        subnet_configuration = [
            ec2.SubnetConfiguration(
                name="public",
                subnet_type=ec2.SubnetType.PUBLIC,
                cidr_mask=24,
                map_public_ip_on_launch=True
            ),
            ec2.SubnetConfiguration(
                name="rds-aurora",
                subnet_type=ec2.SubnetType.PRIVATE_ISOLATED,
                cidr_mask=24
            ),
            ec2.SubnetConfiguration(
                name="eks-private-nat",
                subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS,
                cidr_mask=24,
            ),
            ec2.SubnetConfiguration(
                name="rds-lambda-secret",
                subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS,
                cidr_mask=24,
            ),
        ]

        if config.vpc.automatic_subnet_creation:
            # Create VPC using the construct with configuration from settings
            my_vpc = AutomaticVpc(
                self,
                "VpcConstruct",
                subnet_configuration=subnet_configuration,
                config=config
            )
            self.public_subnets = ec2.SubnetSelection(subnet_group_name="public")
            self.rds_subnets = ec2.SubnetSelection(subnet_group_name="rds-aurora")
            self.eks_private_nat_subnets = ec2.SubnetSelection(subnet_group_name="eks-private-nat")
            self.rds_lambda_subnets = ec2.SubnetSelection(subnet_group_name="rds-lambda-secret")

        else:
            # my_vpc = CustomVpc(
            #     self,
            #     "VpcConstruct",
            #     subnet_configuration=subnet_configuration,
            #     config=config,
            #     availability_zones=self.availability_zones
            # )
            # self.alb_subnets = ec2.SubnetSelection(subnets=self._get_manual_subnets(my_vpc.subnets, "public"))
            # self.rds_subnets = ec2.SubnetSelection(subnets=self._get_manual_subnets(my_vpc.subnets, "rds-aurora"))
            # self.ecs_service_subnets = ec2.SubnetSelection(subnets=self._get_manual_subnets(my_vpc.subnets, "ecs-service"))
            # self.rds_lambda_subnets = ec2.SubnetSelection(subnets=self._get_manual_subnets(my_vpc.subnets, "rds-lambda-secret"))

            my_vpc = CustomVpcV2(
                self,
                "VpcConstruct",
                subnet_configuration=subnet_configuration,
                config=config,
                availability_zones=self.availability_zones
            )

            self.public_subnets = ec2.SubnetSelection(
                subnets=my_vpc.all_subnets.get('public'),
            )
            self.rds_subnets = ec2.SubnetSelection(
                subnets=my_vpc.all_subnets.get('rds-aurora'),
            )
            self.eks_private_nat_subnets = ec2.SubnetSelection(
                subnets=my_vpc.all_subnets.get('eks-private-nat'),
            )
            self.rds_lambda_subnets = ec2.SubnetSelection(
                subnets=my_vpc.all_subnets.get('rds-lambda-secret'),
            )

        self.vpc = my_vpc.vpc_v2

        # Global tags for the stack
        self.s3_vpc_endpoint = self._create_s3_vpc_endpoint()

        self.config.add_stack_global_tags(self)

    def _create_s3_vpc_endpoint(self):
        """
        Create S3 VPC Endpoint to allow EKS pods to access S3 bucket
        without going through the internet gateway.
        """
        s3_endpoint = self.vpc.add_gateway_endpoint(
            "S3Endpoint",
            service=ec2.GatewayVpcEndpointAwsService.S3,
            subnets=[
                ec2.SubnetSelection(subnet_group_name="eks-private-nat"),
            ]
        )

        # Add tags to the endpoint
        s3_endpoint.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                principals=[iam.AnyPrincipal()],
                actions=["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
                resources=[f"arn:aws:s3:::{self.config.prefix('media-bucket')}/*"]
            )
        )

        return s3_endpoint
    # def _get_manual_subnets(self, all_subnets, subnet_group_name):
    #     return [
    #         ec2.Subnet.from_subnet_attributes(
    #             self,
    #             f"{subnet_group_name}Subnet{index}",
    #             subnet_id=subnet.ref,
    #             availability_zone=subnet.availability_zone
    #         ) for index, subnet in enumerate(all_subnets.get(subnet_group_name).get("subnets"))
    #     ]
