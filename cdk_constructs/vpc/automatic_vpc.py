from aws_cdk import aws_ec2 as ec2
from constructs import Construct
from aws_cdk import Tags
from typing import List
from config.base_config import InfrastructureConfig
from aws_cdk import aws_logs as logs
from aws_cdk import aws_iam as iam
from aws_cdk import RemovalPolicy


class AutomaticVpc(Construct):
    def __init__(
            self,
        scope: Construct,
        construct_id: str,
        subnet_configuration: List[ec2.SubnetConfiguration],
        config: InfrastructureConfig,
    ) -> None:
        super().__init__(scope, construct_id)
        self.config = config
        self.subnet_configuration = subnet_configuration
        self.config = config
        self.vpc = self._create_vpc()
        self._tag_subnets_route_tables()
        self._tag_other_vpc_resources()
        self._setup_flow_logs()

    def _create_vpc(self) -> ec2.Vpc:
        """
        Create the VPC with the specified configuration.

        Args:
            construct_id: Unique identifier for the VPC

        Returns:
            Instance of the created VPC
        """

        vpc = ec2.Vpc(
            self, "Vpc",
            vpc_name=self.config.prefix("vpc"),
            ip_addresses=ec2.IpAddresses.cidr(self.config.vpc.cidr),
            max_azs=self.config.vpc.max_azs,
            reserved_azs=self.config.vpc.reserved_azs,
            nat_gateways=self.config.vpc.nat_gateways,
            subnet_configuration=self.subnet_configuration,
            enable_dns_hostnames=True,
            enable_dns_support=True,
        )

        return vpc

    def _tag_subnets_route_tables(self) -> None:
        """
        Add tags to the subnets of the VPC.
        """
        for subnet_configuration in self.subnet_configuration:
            selected = self.vpc.select_subnets(subnet_group_name=subnet_configuration.name).subnets
            for i, subnet in enumerate(selected):
                prefix_shared = self.config.prefix(
                    f"{subnet_configuration.name.lower()}-"
                    f"{subnet_configuration.subnet_type.value.lower().replace('_', '-')}"
                )
                Tags.of(subnet).add(
                    "Name",
                    f"{prefix_shared}-subnet-az{i+1}"
                )
                Tags.of(subnet).add("AZ", subnet.availability_zone)
                for child in subnet.node.children:
                    if isinstance(child, ec2.CfnRouteTable):
                        Tags.of(child).add(
                            "Name",
                            f"{prefix_shared}-route-table-{i+1}"
                        )

    def _tag_other_vpc_resources(self, common_tags: dict = {}):
        """
        Add tags to the resources of the VPC.

        Args:
            common_tags: Dictionary containing common tags for all resources
        """
        nat_gateways = []
        internet_gateways = []
        eips = []

        all_resources = self.vpc.node.find_all()
        for child in all_resources:
            # NAT Gateways
            if isinstance(child, ec2.CfnNatGateway):
                nat_gateways.append(child)
            # Internet Gateway
            if isinstance(child, ec2.CfnInternetGateway):
                internet_gateways.append(child)

            if isinstance(child, ec2.CfnEIP):
                eips.append(child)

        for index, nat_gateway in enumerate(nat_gateways):
            Tags.of(nat_gateway).add(
                "Name",
                self.config.prefix(f"nat-gateway-{index+1}")
            )
            for k, v in common_tags.items():
                Tags.of(nat_gateway).add(k, v)

        for index, internet_gateway in enumerate(internet_gateways):
            Tags.of(internet_gateway).add(
                "Name",
                self.config.prefix(f"igw-{index+1}")
            )
            for k, v in common_tags.items():
                Tags.of(internet_gateway).add(k, v)

        for index, eip in enumerate(eips):
            Tags.of(eip).add(
                "Name",
                self.config.prefix(f"eip-{index+1}")
            )
            for k, v in common_tags.items():
                Tags.of(eip).add(k, v)

    def _setup_flow_logs(self) -> None:
        """
        Configure VPC Flow Logs for the VPC.
        """
        # Create log group
        log_group = logs.LogGroup(
            self, "VpcFlowLogs",
            log_group_name=f"/{self.config.project_name}/{self.config.env_name_str}/vpc/{self.config.prefix('vpc')}/flow-logs",
            retention=logs.RetentionDays.ONE_MONTH,
            removal_policy=RemovalPolicy.DESTROY
        )

        # Create IAM role for Flow Logs
        flow_logs_role = iam.Role(
            self, "VpcFlowLogsRole",
            assumed_by=iam.ServicePrincipal("vpc-flow-logs.amazonaws.com"),
            role_name=self.config.prefix("vpc-flow-logs-role")
        )

        # Add necessary permissions to the role
        flow_logs_role.add_to_policy(
            iam.PolicyStatement(
                actions=[
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents",
                    "logs:DescribeLogGroups",
                    "logs:DescribeLogStreams"
                ],
                resources=["*"]
            )
        )

        # Configure Flow Logs
        self.vpc.add_flow_log(
            "VpcFlowLogs",
            destination=ec2.FlowLogDestination.to_cloud_watch_logs(log_group, flow_logs_role),
            traffic_type=ec2.FlowLogTrafficType.ALL,
        )
