from aws_cdk import aws_ec2 as ec2
from constructs import Construct
from aws_cdk import Tags
from typing import List, Dict
from config.base_config import InfrastructureConfig
from aws_cdk import aws_logs as logs
from aws_cdk import aws_iam as iam
from aws_cdk import RemovalPolicy
from aws_cdk import CfnTag


class CustomVpc(Construct):
    def __init__(self,
                 scope: Construct,
                 construct_id: str,
                 subnet_configuration: List[ec2.SubnetConfiguration],
                 config: InfrastructureConfig,
                 availability_zones: List[str],
                 **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        self.config = config
        self.subnet_configuration = subnet_configuration
        self.availability_zones = availability_zones

        # Create VPC
        self.cfn_vpc = self._create_vpc()

        # Create Internet Gateway
        self.internet_gateway = self._create_internet_gateway()

        # Create subnets and route tables
        self.subnets = self._create_subnets()

        # Create NAT Gateways if needed
        self.nat_gateways = self._create_nat_gateways() if self.config.vpc.nat_gateways > 0 else []

        # Create and configure route tables
        self.route_tables = self._create_route_tables()

        # Associate route tables with subnets
        self._create_route_table_associations()

        self.vpc = self._create_high_level_vpc()

    def _create_vpc(self) -> ec2.CfnVPC:
        """
        Create the VPC with the specified configuration.
        """
        return ec2.CfnVPC(
            self, "Vpc",
            cidr_block=self.config.vpc.cidr,
            enable_dns_support=True,
            enable_dns_hostnames=True,
            tags=[CfnTag(key="Name", value=self.config.prefix("vpc"))]
        )

    def _create_internet_gateway(self) -> ec2.CfnInternetGateway:
        """
        Create and attach an Internet Gateway to the VPC.
        """
        # Create Internet Gateway
        internet_gateway = ec2.CfnInternetGateway(
            self, "InternetGateway",
            tags=[CfnTag(key="Name", value=self.config.prefix("igw"))]
        )

        # Attach Internet Gateway to VPC
        ec2.CfnVPCGatewayAttachment(
            self, "InternetGatewayAttachment",
            vpc_id=self.cfn_vpc.ref,
            internet_gateway_id=internet_gateway.ref
        )

        return internet_gateway

    def _create_subnets(self) -> Dict[str, List[ec2.CfnSubnet]]:
        """
        Create subnets based on the subnet configuration.
        Returns a dictionary mapping subnet type to list of subnets.
        """
        subnets = {}
        subnet_index = 0

        for subnet_config in self.subnet_configuration:
            subnet_list = []
            for az_index in range(self.config.vpc.max_azs):
                az = self.availability_zones[az_index]

                # Calculate CIDR block for this subnet
                cidr_block = self._calculate_subnet_cidr(
                    self.config.vpc.cidr,
                    subnet_index,
                    subnet_config.cidr_mask
                )

                # Create subnet
                subnet = ec2.CfnSubnet(
                    self, f"{subnet_config.name}Subnet{az_index+1}",
                    vpc_id=self.cfn_vpc.ref,
                    availability_zone=az,
                    cidr_block=cidr_block,
                    map_public_ip_on_launch=subnet_config.subnet_type == ec2.SubnetType.PUBLIC,
                    tags=[
                        CfnTag(key="Name", value=self.config.prefix(f"{subnet_config.name}-subnet-az{az_index+1}")),
                        CfnTag(key="Type", value=subnet_config.subnet_type.value)
                    ]
                )

                subnet_list.append(subnet)
                subnet_index += 1

            subnets[subnet_config.name] = {
                "subnets": subnet_list,
                "subnet_type": subnet_config.subnet_type
            }

        return subnets

    def _get_public_subnets(self) -> List[ec2.CfnSubnet]:
        for subnet_attributes in self.subnets.values():
            if subnet_attributes["subnet_type"] == ec2.SubnetType.PUBLIC:
                return subnet_attributes["subnets"]
        return []

    def _create_nat_gateways(self) -> List[ec2.CfnNatGateway]:
        """
        Create NAT Gateways in public subnets.
        """
        nat_gateways = []
        public_subnets = self._get_public_subnets()

        for i in range(self.config.vpc.nat_gateways):
            # Create Elastic IP for NAT Gateway
            eip = ec2.CfnEIP(
                self, f"NatGatewayEip{i+1}",
                domain="vpc",
                tags=[CfnTag(key="Name", value=self.config.prefix(f"nat-eip-{i+1}"))]
            )

            # Create NAT Gateway in public subnet
            nat_gateway = ec2.CfnNatGateway(
                self, f"NatGateway{i+1}",
                allocation_id=eip.attr_allocation_id,
                subnet_id=public_subnets[i % len(public_subnets)].ref,
                tags=[CfnTag(key="Name", value=self.config.prefix(f"nat-gateway-{i+1}"))]
            )

            nat_gateways.append(nat_gateway)

        return nat_gateways

    def _create_route_tables(self) -> Dict[str, List[ec2.CfnRouteTable]]:
        """
        Create route tables for each subnet type (Public, Private, Private with Egress) per AZ.
        Returns a dictionary mapping subnet type to list of route tables (one per AZ).
        """
        route_tables = {}
        subnet_types = {
            "Public": ec2.SubnetType.PUBLIC,
            "Private": ec2.SubnetType.PRIVATE_ISOLATED,
            "PrivateWithEgress": ec2.SubnetType.PRIVATE_WITH_EGRESS
        }

        # Create route tables for each subnet type
        for subnet_type_name, subnet_type in subnet_types.items():
            route_table_list = []
            for az_index in range(self.config.vpc.max_azs):
                # Create route table
                route_table = ec2.CfnRouteTable(
                    self, f"{subnet_type_name}RouteTable{az_index+1}",
                    vpc_id=self.cfn_vpc.ref,
                    tags=[
                        CfnTag(key="Name", value=self.config.prefix(f"{subnet_type_name.lower()}-rt-az{az_index+1}")),
                        CfnTag(key="Type", value=subnet_type.value)
                    ]
                )

                # Add routes based on subnet type
                if subnet_type == ec2.SubnetType.PUBLIC:
                    # Public subnet route to Internet Gateway
                    ec2.CfnRoute(
                        self, f"{subnet_type_name}PublicRoute{az_index+1}",
                        route_table_id=route_table.ref,
                        destination_cidr_block="0.0.0.0/0",
                        gateway_id=self.internet_gateway.ref
                    )
                elif subnet_type == ec2.SubnetType.PRIVATE_WITH_EGRESS:
                    # Private subnet route to NAT Gateway
                    if self.nat_gateways:
                        nat_gateway_index = az_index % len(self.nat_gateways)
                        ec2.CfnRoute(
                            self, f"{subnet_type_name}PrivateRoute{az_index+1}",
                            route_table_id=route_table.ref,
                            destination_cidr_block="0.0.0.0/0",
                            nat_gateway_id=self.nat_gateways[nat_gateway_index].ref
                        )

                route_table_list.append(route_table)

            route_tables[subnet_type_name] = route_table_list

        return route_tables

    def _create_route_table_associations(self) -> None:
        """
        Associate route tables with their respective subnets.
        Each subnet is associated with the route table matching its type in its AZ.
        """
        subnet_type_mapping = {
            ec2.SubnetType.PUBLIC: "Public",
            ec2.SubnetType.PRIVATE_ISOLATED: "Private",
            ec2.SubnetType.PRIVATE_WITH_EGRESS: "PrivateWithEgress"
        }

        for subnet_config in self.subnet_configuration:
            subnets = self.subnets.get(subnet_config.name, {}).get("subnets", [])
            route_tables = self.route_tables.get(subnet_type_mapping[subnet_config.subnet_type], [])

            # Associate each subnet with the route table for its type in the same AZ
            for az_index, subnet in enumerate(subnets):
                if az_index < len(route_tables):
                    ec2.CfnSubnetRouteTableAssociation(
                        self, f"{subnet_config.name}RouteTableAssociation{az_index+1}",
                        subnet_id=subnet.ref,
                        route_table_id=route_tables[az_index].ref
                    )

    def _calculate_subnet_cidr(self, vpc_cidr: str, subnet_index: int, cidr_mask: int) -> str:
        """
        Calculate the CIDR block for a subnet based on the VPC CIDR and subnet index.
        """
        # Split the VPC CIDR into IP and prefix
        vpc_ip, vpc_prefix = vpc_cidr.split('/')
        vpc_prefix = int(vpc_prefix)

        # Convert IP to integer
        ip_parts = list(map(int, vpc_ip.split('.')))
        ip_int = (ip_parts[0] << 24) + (ip_parts[1] << 16) + (ip_parts[2] << 8) + ip_parts[3]

        # Calculate subnet size
        subnet_size = 1 << (32 - cidr_mask)

        # Calculate new IP
        new_ip_int = ip_int + (subnet_index * subnet_size)

        # Convert back to IP string
        new_ip_parts = [
            (new_ip_int >> 24) & 0xFF,
            (new_ip_int >> 16) & 0xFF,
            (new_ip_int >> 8) & 0xFF,
            new_ip_int & 0xFF
        ]
        new_ip = '.'.join(map(str, new_ip_parts))

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
