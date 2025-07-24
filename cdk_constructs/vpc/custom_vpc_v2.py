from aws_cdk import aws_ec2 as ec2
from aws_cdk import aws_ec2_alpha as ec2_alpha
from constructs import Construct
from aws_cdk import Tags
from typing import List, Dict
from config.base_config import InfrastructureConfig
from aws_cdk import aws_logs as logs
from aws_cdk import aws_iam as iam
from aws_cdk import RemovalPolicy
from aws_cdk import CfnTag


class CustomVpcV2(Construct):
    def __init__(self,
                 scope: Construct,
                 construct_id: str,
                 subnet_configuration: List[ec2.SubnetConfiguration],
                 config: InfrastructureConfig,
                 availability_zones: List[str],
                 **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        self.config = config
        self.all_subnets = {}
        self.subnet_configuration = subnet_configuration
        self.availability_zones = availability_zones
        # Initialize subnet index as class attribute
        self.subnet_index = 0

        # Create VPC
        self.vpc_v2 = self._create_vpc_v2()

        # Create Internet Gateway
        self.internet_gateway = self._create_internet_gateway()

        self.public_route_table = self._create_public_route_table()

        self.public_subnets, self.public_default_subnets = self._create_public_subnets()

        # Create NAT Gateways if needed
        self.nat_gateways = self._create_nat_gateways() if self.config.vpc.nat_gateways > 0 else []

        self.private_nat_route_tables = self._create_private_nat_route_tables()

        self.private_isolated_route_table = self._create_private_isolated_route_table()

        self.private_subnets = self._create_private_subnets()

        self._setup_flow_logs()

    def _create_vpc_v2(self) -> ec2_alpha.VpcV2:
        """
        Create the VPC with the specified configuration.
        """
        return ec2_alpha.VpcV2(
            self, "Vpc",
            primary_address_block=ec2_alpha.IpAddresses.ipv4(self.config.vpc.cidr, cidr_block_name="primary"),
            enable_dns_support=True,
            enable_dns_hostnames=True,
            vpc_name=self.config.prefix("vpc"),
        )

    def _create_internet_gateway(self) -> ec2_alpha.InternetGateway:
        """
        Create and attach an Internet Gateway to the VPC.
        """

        # Create Internet Gateway
        igw = ec2_alpha.InternetGateway(
            self, "InternetGateway",
            vpc=self.vpc_v2,
            internet_gateway_name=self.config.prefix("igw"),
        )
        Tags.of(igw).add(
            "Name",
            self.config.prefix(f"igw")
        )

        return igw

    def _create_public_route_table(self) -> ec2_alpha.RouteTable:

        route_table = ec2_alpha.RouteTable(
            self, f"PublicRouteTable",
            vpc=self.vpc_v2,
            route_table_name=self.config.prefix(
                f"public-route-table"),
        )

        ec2_alpha.Route(
            self, f"PublicRoute",
            route_table=route_table,
            destination="0.0.0.0/0",
            target=ec2_alpha.RouteTargetType(gateway=self.internet_gateway),
            route_name=self.config.prefix(f"public-route")
        )

        return route_table

    def _create_private_isolated_route_table(self) -> ec2_alpha.RouteTable:

        route_table = ec2_alpha.RouteTable(
            self, f"PrivateIsolatedRouteTable",
            vpc=self.vpc_v2,
            route_table_name=self.config.prefix(f"private-isolated-route-table"),
        )

        return route_table

    def _create_private_nat_route_tables(self) -> List[ec2_alpha.RouteTable]:
        """
        Create private route tables.
        """
        private_route_tables = []
        for i in range(self.config.vpc.nat_gateways):
            # az = self.availability_zones[i]
            route_table = ec2_alpha.RouteTable(
                self, f"PrivateNatRouteTableAz{i+1}",
                vpc=self.vpc_v2,
                route_table_name=self.config.prefix(f"private-route-table-nat-az{i+1}"),
            )
            ec2_alpha.Route(
                self, f"PrivateNatRouteAz{i+1}",
                route_table=route_table,
                destination="0.0.0.0/0",
                target=ec2_alpha.RouteTargetType(gateway=self.nat_gateways[i % len(self.nat_gateways)]),
                route_name=self.config.prefix(f"private-route-nat-az{i+1}")
            )
            private_route_tables.append(route_table)

        return private_route_tables

    def _create_subnet_with_config(self, az_index: int, subnet_config: ec2.SubnetConfiguration, route_table: ec2_alpha.RouteTable = None) -> ec2_alpha.SubnetV2:
        """
        Create subnets for a given configuration.
        """
        az = self.availability_zones[az_index]
        cidr_block = self._calculate_subnet_cidr(self.config.vpc.cidr, subnet_config.cidr_mask)

        subnet = ec2_alpha.SubnetV2(
            self, f"{subnet_config.name}Subnet{az_index+1}",
            subnet_name=self.config.prefix(f"{subnet_config.name}-subnet-az{az_index+1}"),
            vpc=self.vpc_v2,
            availability_zone=az,
            ipv4_cidr_block=ec2_alpha.IpCidr(cidr_block),
            route_table=route_table,
            subnet_type=subnet_config.subnet_type,
            map_public_ip_on_launch=subnet_config.subnet_type == ec2.SubnetType.PUBLIC
        )

        # Tag manually since subnet_name doesn't work
        Tags.of(subnet).add("Name", self.config.prefix(f"{subnet_config.name}-subnet-az{az_index+1}"))

        return subnet

    def _create_public_subnets(self) -> List[ec2_alpha.SubnetV2]:
        """
        Create public subnets.
        """

        all_public_subnet_list = []
        public_default_subnet_list = []
        subnet_default = True
        for subnet_config in self.subnet_configuration:
            if subnet_config.subnet_type != ec2.SubnetType.PUBLIC:
                continue
            subnet_config_list = []
            for az_index in range(self.config.vpc.max_azs):
                subnet = self._create_subnet_with_config(az_index, subnet_config, self.public_route_table)
                subnet_config_list.append(subnet)

                if subnet_default:
                    public_default_subnet_list.append(subnet)

            subnet_default = False

            self._add_subnets_to_all_subnets(subnet_config.name, subnet_config_list)
            all_public_subnet_list.extend(subnet_config_list)

        return all_public_subnet_list, public_default_subnet_list

    def _create_private_subnets(self) -> List[ec2_alpha.SubnetV2]:
        """
        Create private subnets.
        """
        privatesubnet_list = []

        for subnet_config in self.subnet_configuration:
            if subnet_config.subnet_type == ec2.SubnetType.PUBLIC:
                continue
            subnet_config_list = []
            for az_index in range(self.config.vpc.max_azs):
                if subnet_config.subnet_type == ec2.SubnetType.PRIVATE_WITH_EGRESS:
                    route_table = self.private_nat_route_tables[az_index % len(self.private_nat_route_tables)]
                else:
                    route_table = self.private_isolated_route_table

                subnet = self._create_subnet_with_config(az_index, subnet_config, route_table)
                subnet_config_list.append(subnet)

            self._add_subnets_to_all_subnets(subnet_config.name, subnet_config_list)
            privatesubnet_list.extend(subnet_config_list)

        return privatesubnet_list

    def _create_nat_gateways(self) -> List[ec2_alpha.NatGateway]:
        """
        Create NAT Gateways in public subnets.
        """
        nat_gateways = []

        for i in range(self.config.vpc.nat_gateways):
            # Create NAT Gateway in public subnet
            nat_gateway = ec2_alpha.NatGateway(
                self, f"NatGateway{i+1}",
                vpc=self.vpc_v2,
                subnet=self.public_default_subnets[i % len(self.public_default_subnets)],
                nat_gateway_name=self.config.prefix(f"nat-gateway-{i+1}")
            )

            nat_gateways.append(nat_gateway)

        return nat_gateways

    def _calculate_subnet_cidr(self, vpc_cidr: str, cidr_mask: int) -> str:
        """
        Calculate the CIDR block for a subnet based on the VPC CIDR and current subnet index.
        The subnet_index is automatically incremented after each call.

        Args:
            vpc_cidr: The VPC CIDR block (e.g., "10.0.0.0/16")
            cidr_mask: The CIDR mask for the subnet (e.g., 24)

        Returns:
            The calculated CIDR block for the subnet (e.g., "10.0.1.0/24")
        """
        # Split the VPC CIDR into IP and prefix
        vpc_ip, vpc_prefix = vpc_cidr.split('/')
        vpc_prefix = int(vpc_prefix)

        # Convert IP to integer
        ip_parts = list(map(int, vpc_ip.split('.')))
        ip_int = (ip_parts[0] << 24) + (ip_parts[1] << 16) + (ip_parts[2] << 8) + ip_parts[3]

        # Calculate subnet size
        subnet_size = 1 << (32 - cidr_mask)

        # Calculate new IP using current subnet index
        new_ip_int = ip_int + (self.subnet_index * subnet_size)

        # Convert back to IP string
        new_ip_parts = [
            (new_ip_int >> 24) & 0xFF,
            (new_ip_int >> 16) & 0xFF,
            (new_ip_int >> 8) & 0xFF,
            new_ip_int & 0xFF
        ]
        new_ip = '.'.join(map(str, new_ip_parts))

        # Increment subnet index for next call
        self.subnet_index += 1

        return f"{new_ip}/{cidr_mask}"

    def _create_high_level_vpc(self) -> ec2.Vpc:
        """
        Create a high-level VPC object using VpcAttributes.
        """
        # Create subnet groups based on our configuration
        subnet_type_groups = {
            ec2.SubnetType.PUBLIC: [],
            ec2.SubnetType.PRIVATE_ISOLATED: [],
            ec2.SubnetType.PRIVATE_WITH_EGRESS: []
        }
        for subnet_attributes in self.subnets.values():
            subnet_type_groups[subnet_attributes["subnet_type"]].extend(subnet_attributes["subnets"])

        # Create VPC from attributes with explicit subnet group names
        return ec2.Vpc.from_vpc_attributes(
            self, "VpcFromAttributes",
            vpc_id=self.cfn_vpc.ref,
            availability_zones=self.availability_zones,
            public_subnet_ids=[subnet.ref for subnet in subnet_type_groups[ec2.SubnetType.PUBLIC]],
            isolated_subnet_ids=[subnet.ref for subnet in subnet_type_groups[ec2.SubnetType.PRIVATE_ISOLATED]],
            private_subnet_ids=[subnet.ref for subnet in subnet_type_groups[ec2.SubnetType.PRIVATE_WITH_EGRESS]],
            vpc_cidr_block=self.config.vpc.cidr
        )

    def _add_subnets_to_all_subnets(self, subnet_config_name: str, subnets: List[ec2_alpha.SubnetV2]):
        """
        Add subnets to all_subnets dictionary.
        """
        self.all_subnets[subnet_config_name] = subnets

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
        self.vpc_v2.add_flow_log(
            "VpcFlowLogs",
            destination=ec2.FlowLogDestination.to_cloud_watch_logs(log_group, flow_logs_role),
            traffic_type=ec2.FlowLogTrafficType.ALL,
        )
