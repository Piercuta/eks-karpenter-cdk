from aws_cdk import (
    aws_ec2 as ec2,
    aws_iam as iam,
    aws_eks as eks,
    Tags,
    CfnOutput,
    CfnTag
)
from config.base_config import InfrastructureConfig
from constructs import Construct
import json
from string import Template
from .eks_utils import create_standard_admin_access_entry, create_pod_identity_association


class EksCluster(Construct):
    """
    EKS Cluster construct for GitOps architecture.

    Creates a minimal EKS cluster with essential addons (kube-proxy, coredns, vpc-cni, pod-identity-agent).
    Additional addons and workloads will be managed via ArgoCD.
    Includes IAM roles for future services like AWS Load Balancer Controller,
    Karpenter, and other EKS addons.
    """

    def __init__(self, scope: Construct, id: str,
                 vpc: ec2.Vpc,
                 public_subnets: ec2.SubnetSelection,
                 eks_private_nat_subnets: ec2.SubnetSelection,
                 eks_workload_sg: ec2.SecurityGroup,
                 eks_fastapi_sg: ec2.SecurityGroup,
                 alb_security_group: ec2.SecurityGroup,
                 eks_cluster_additional_sg: ec2.SecurityGroup,
                 db_endpoint: str,
                 db_secret_arn: str,
                 config: InfrastructureConfig,
                 **kwargs) -> None:
        super().__init__(scope, id)

        self.vpc = vpc

        self.public_subnets = public_subnets
        self.eks_private_nat_subnets = eks_private_nat_subnets

        self.eks_workload_sg = eks_workload_sg
        self.eks_fastapi_sg = eks_fastapi_sg
        self.alb_security_group = alb_security_group
        self.eks_cluster_additional_sg = eks_cluster_additional_sg
        self.db_endpoint = db_endpoint
        self.db_secret_arn = db_secret_arn
        self.config = config

        self.cluster_name = self.config.prefix("eks-cluster")

        # Create IAM roles first
        self.cluster_role = self._create_cluster_role()
        self.node_role = self._create_node_role()

        # Tags subnets and security groups
        self._tags_subnets_and_security_groups()

        # Create the EKS cluster using low-level constructs
        self.eks_cluster = self._create_eks_cluster()

        # Create IAM OIDC provider
        self.oidc_provider = self._create_oidc_provider()

        # Create node group with launch template
        self.node_group = self._create_node_group()

        # Create essential EKS addons
        self.pod_identity_agent_addon = self._create_pod_identity_agent_addon()

        self.metrics_server_addon = self._create_metrics_server_addon()
        self.vpc_cni_addon = self._create_vpc_cni_addon()
        self.kube_proxy_addon = self._create_kube_proxy_addon()
        self.coredns_addon = self._create_coredns_addon()
        self.external_dns_addon = self._create_external_dns_addon()
        self.cloudwatch_observability_addon = self._create_cloudwatch_observability_addon()

        # IAM role for karpenter ec2 new nodes
        self.karpenter_node_role = self._create_karpenter_node_role()

        # IAM roles for all service accounts
        self.karpenter_controller_role = self._create_karpenter_controller_role()
        create_pod_identity_association(
            scope=self,
            id="Karpenter",
            cluster_name=self.eks_cluster.name,
            namespace="kube-system",
            service_account="karpenter",
            role_arn=self.karpenter_controller_role.get_att("Arn").to_string(),
            pod_identity_agent_dependency=self.pod_identity_agent_addon
        )

        self.alb_controller_role = self._create_alb_controller_role()
        create_pod_identity_association(
            scope=self,
            id="AlbController",
            cluster_name=self.eks_cluster.name,
            namespace="kube-system",
            service_account="aws-load-balancer-controller",
            role_arn=self.alb_controller_role.get_att("Arn").to_string(),
            pod_identity_agent_dependency=self.pod_identity_agent_addon
        )

        # Create access entries...
        create_standard_admin_access_entry(
            scope=self,
            id="AccessEntrySelfAdmin",
            cluster_name=self.cluster_name,
            principal_arn="arn:aws:iam::532673134317:role/aws-reserved/sso.amazonaws.com/eu-west-1/AWSReservedSSO_AdministratorAccess_ecdb820f0c77380d",
            cluster_dependency=self.eks_cluster
        )
        # self._create_access_entries()

        # Add security group ingress
        self._add_security_group_ingress()

        # # Create outputs for GitOps
        self._create_outputs()

    def _create_oidc_provider(self) -> eks.OpenIdConnectProvider:
        """Create IAM OIDC provider. Usefull for IRSA."""

        provider = eks.OpenIdConnectProvider(
            self, "OidcProvider",
            url=self.eks_cluster.get_att("OpenIdConnectIssuerUrl").to_string(),
        )

        return provider

    def _create_cluster_role(self) -> iam.Role:
        """Create IAM role for EKS cluster."""
        trust_policy = iam.PolicyDocument(
            statements=[
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    principals=[
                        iam.ServicePrincipal("eks.amazonaws.com")
                    ],
                    actions=[
                        "sts:AssumeRole",
                        "sts:TagSession"
                    ]
                )
            ]
        )
        role = iam.CfnRole(
            self, "EksClusterRole",
            role_name=self.config.prefix("eks-cluster-role"),
            assume_role_policy_document=trust_policy,
            description="IAM role for EKS cluster",
            managed_policy_arns=[
                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonEKSClusterPolicy").managed_policy_arn,
                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonEKSVPCResourceController").managed_policy_arn,
            ]
        )

        return role

    def _create_node_role(self) -> iam.Role:
        """Create IAM role for EKS nodes."""
        role = iam.Role(
            self, "EksNodeRole",
            role_name=self.config.prefix("eks-node-role"),
            assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonEKSWorkerNodePolicy"),
                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonEC2ContainerRegistryPullOnly"),
                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonSSMManagedInstanceCore"),
            ],
            description="IAM role for EKS worker nodes",
        )

        # Add custom policies for node operations
        role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=[
                "ec2:*",
                "elasticloadbalancing:*",
                "ecr:*",
                "logs:*",
                "cloudwatch:*",
                "autoscaling:*",
                "iam:GetRole",
                "iam:ListRoles",
                "iam:PassRole",
                "kms:*",
                "secretsmanager:*",
                "ssm:*",
                "s3:*",
            ],
            resources=["*"]
        ))

        return role

    def _create_karpenter_node_role(self) -> iam.Role:
        """Create IAM role for Karpenter nodes."""

        role = iam.Role(
            self, "KarpenterNodeRole",
            role_name=self.config.prefix("karpenter-node-role"),
            assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonEKSWorkerNodePolicy"),
                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonEKS_CNI_Policy"),
                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonEC2ContainerRegistryPullOnly"),
                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonSSMManagedInstanceCore"),
            ],
            description="IAM role for Karpenter-managed nodes",
        )
        return role

    def _create_karpenter_controller_role(self) -> iam.CfnRole:
        """Create IAM role for Karpenter controller."""

        with open("assets/policies/karpenter_controller_policy.json", "r") as f:
            file_content = f.read()

        # Remplacement des variables d'environnement style ${VAR}
        template = Template(file_content)
        substituted_content = template.safe_substitute(
            AWS_PARTITION="aws",
            AWS_ACCOUNT_ID=self.config.aws.account,
            AWS_REGION=self.config.aws.region_str,
            CLUSTER_NAME=self.cluster_name,
            KARPENTER_NODE_ROLE_NAME=self.karpenter_node_role.role_name
        )

        # Charger ensuite le JSON
        policy_doc = json.loads(substituted_content)
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
            self, "KarpenterControllerRole",
            role_name=self.config.prefix("karpenter-controller-role"),
            assume_role_policy_document=trust_policy,
            policies=[
                iam.CfnRole.PolicyProperty(
                    policy_name="KarpenterControllerPolicy",
                    policy_document=iam.PolicyDocument.from_json(policy_doc)
                )
            ]
        )

        return role

    def _create_alb_controller_role(self) -> iam.CfnRole:
        """Create IAM role for AWS Load Balancer Controller."""

        with open("assets/policies/alb_controller_iam_policy.json", "r") as f:
            policy_doc = json.load(f)

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
            self, "AlbControllerRole",
            role_name=self.config.prefix("alb-controller-role"),
            assume_role_policy_document=trust_policy,
            description="IAM role for AWS Load Balancer Controller",
            policies=[
                iam.CfnRole.PolicyProperty(
                    policy_name="AlbControllerPolicy",
                    policy_document=iam.PolicyDocument.from_json(policy_doc)
                )
            ]
        )

        return role

    def _create_vpc_cni_role(self) -> iam.CfnRole:
        """Create IAM role for Amazon VPC CNI."""

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
            self, "VpcCniRole",
            role_name=self.config.prefix("vpc-cni-role"),
            assume_role_policy_document=trust_policy,
            description="IAM role for Amazon VPC CNI",
            managed_policy_arns=[
                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonEKS_CNI_Policy").managed_policy_arn
            ]
        )

        return role

    def _create_external_dns_role(self) -> iam.CfnRole:
        """Create IAM role for External DNS."""

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
            self, "ExternalDnsRole",
            role_name=self.config.prefix("external-dns-role"),
            assume_role_policy_document=trust_policy,
            description="IAM role for External DNS",
            managed_policy_arns=[
                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonRoute53FullAccess").managed_policy_arn,
            ]
        )

        return role

    def _create_cloudwatch_observability_role(self) -> iam.CfnRole:
        """Create IAM role for CloudWatch Observability."""

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
            self, "CloudWatchObservabilityRole",
            role_name=self.config.prefix("cloudwatch-observability-role"),
            assume_role_policy_document=trust_policy,
            description="IAM role for CloudWatch Observability",
            managed_policy_arns=[
                iam.ManagedPolicy.from_aws_managed_policy_name("CloudWatchAgentServerPolicy").managed_policy_arn,
            ]
        )

        return role

    def _tags_subnets_and_security_groups(self):
        """Tags subnets and security groups for karpenter and load balancer ingress"""

        for subnet in self.eks_private_nat_subnets.subnets:
            Tags.of(subnet).add("kubernetes.io/cluster/" + self.cluster_name, "owned")
            Tags.of(subnet).add("kubernetes.io/role/internal-elb", "1")
            Tags.of(subnet).add("karpenter.sh/discovery", self.cluster_name)

        for subnet in self.public_subnets.subnets:
            Tags.of(subnet).add("kubernetes.io/cluster/" + self.cluster_name, "owned")
            Tags.of(subnet).add("kubernetes.io/role/elb", "1")
            Tags.of(subnet).add("karpenter.sh/discovery", self.cluster_name)

        Tags.of(self.eks_workload_sg).add("karpenter.sh/discovery", self.cluster_name)
        Tags.of(self.eks_workload_sg).add("kubernetes.io/cluster/" + self.cluster_name, "owned")
        Tags.of(self.eks_workload_sg).add("elb.ingress.k8s.aws/targetShared", "true")

    def _create_eks_cluster(self) -> eks.CfnCluster:
        """Create EKS cluster using low-level constructs."""

        # Prepare subnet configuration
        subnet_ids = [
            subnet.subnet_id for subnet in self.eks_private_nat_subnets.subnets + self.public_subnets.subnets]

        # Create cluster using CfnCluster for maximum control
        cluster = eks.CfnCluster(
            self, "EksCluster",
            name=self.cluster_name,
            version=self.config.eks.cluster_version,
            access_config=eks.CfnCluster.AccessConfigProperty(
                authentication_mode="API_AND_CONFIG_MAP",
                bootstrap_cluster_creator_admin_permissions=True,
            ),
            # we install addons later
            bootstrap_self_managed_addons=False,
            role_arn=self.cluster_role.get_att("Arn").to_string(),
            resources_vpc_config=eks.CfnCluster.ResourcesVpcConfigProperty(
                subnet_ids=subnet_ids,
                # security_group_ids=[self.eks_cluster_additional_sg.security_group_id],
                endpoint_private_access=False,
                endpoint_public_access=True
            ),
            logging=eks.CfnCluster.LoggingProperty(
                cluster_logging=eks.CfnCluster.ClusterLoggingProperty(
                    enabled_types=[
                        eks.CfnCluster.LoggingTypeConfigProperty(
                            type="api",
                        ),
                        eks.CfnCluster.LoggingTypeConfigProperty(
                            type="audit",
                        ),
                        eks.CfnCluster.LoggingTypeConfigProperty(
                            type="authenticator",
                        ),
                        eks.CfnCluster.LoggingTypeConfigProperty(
                            type="controllerManager",
                        ),
                        eks.CfnCluster.LoggingTypeConfigProperty(
                            type="scheduler",
                        ),
                    ]
                )
            ),
            # Essential addons will be added separately for better control
        )

        # Add tags
        Tags.of(cluster).add("Purpose", "GitOps-Cluster")
        Tags.of(cluster).add("ManagedBy", "CDK")
        Tags.of(cluster).add("Environment", self.config.env_name_str)
        Tags.of(cluster).add("Project", self.config.project_name)

        return cluster

    def _create_launch_template(self) -> ec2.CfnLaunchTemplate:
        """Create launch template for EKS nodes."""

        launch_template = ec2.CfnLaunchTemplate(
            self, "EksNodeLaunchTemplate",
            launch_template_name=self.config.prefix("eks-node-launch-template"),
            launch_template_data=ec2.CfnLaunchTemplate.LaunchTemplateDataProperty(
                instance_type=self.config.eks.node_group.instance_type,
                security_group_ids=[self.eks_cluster.get_att("ClusterSecurityGroupId").to_string()],
                monitoring=ec2.CfnLaunchTemplate.MonitoringProperty(
                    enabled=True
                ),
                block_device_mappings=[
                    ec2.CfnLaunchTemplate.BlockDeviceMappingProperty(
                        device_name="/dev/xvda",
                        ebs=ec2.CfnLaunchTemplate.EbsProperty(
                            volume_size=20,
                            volume_type="gp3",
                            delete_on_termination=True,
                            encrypted=True
                        )
                    )
                ],
                metadata_options=ec2.CfnLaunchTemplate.MetadataOptionsProperty(
                    http_put_response_hop_limit=2,
                    http_tokens="required"
                ),
                tag_specifications=[
                    ec2.CfnLaunchTemplate.TagSpecificationProperty(
                        resource_type="instance",
                        tags=[
                            CfnTag(key="Name", value=self.config.prefix("eks-default-node")),
                            CfnTag(key="Environment", value=self.config.env_name_str),
                            CfnTag(key="ProjectName", value=self.config.project_name),
                        ]
                    ),
                    ec2.CfnLaunchTemplate.TagSpecificationProperty(
                        resource_type="volume",
                        tags=[
                            CfnTag(key="Name", value=self.config.prefix("eks-volume")),
                        ]
                    )
                ]
            ),
            tag_specifications=[
                ec2.CfnLaunchTemplate.LaunchTemplateTagSpecificationProperty(
                    resource_type="launch-template",
                    tags=[
                        CfnTag(key="Name", value=self.config.prefix("eks-lt")),
                    ]
                )
            ]
        )

        return launch_template

    def _create_node_group(self) -> eks.CfnNodegroup:
        """Create EKS node group with launch template."""

        # Create launch template
        launch_template = self._create_launch_template()

        # public_selection = self.vpc.select_subnets(
        #     subnet_group_name="public"
        # )

        # Create node group
        node_group = eks.CfnNodegroup(
            self, "EksNodeGroup",
            cluster_name=self.eks_cluster.name,
            nodegroup_name=self.config.prefix("eks-nodegroup"),
            node_role=self.node_role.role_arn,
            # subnets=[subnet.subnet_id for subnet in public_selection.subnets],
            subnets=[subnet.subnet_id for subnet in self.eks_private_nat_subnets.subnets],
            ami_type="AL2023_x86_64_STANDARD",
            capacity_type="ON_DEMAND",
            force_update_enabled=False,
            launch_template=eks.CfnNodegroup.LaunchTemplateSpecificationProperty(
                id=launch_template.ref,
                version=launch_template.attr_latest_version_number
            ),
            scaling_config=eks.CfnNodegroup.ScalingConfigProperty(
                min_size=self.config.eks.node_group.min_size,
                max_size=self.config.eks.node_group.max_size,
                desired_size=self.config.eks.node_group.desired_size
            ),
            update_config=eks.CfnNodegroup.UpdateConfigProperty(
                max_unavailable=1
            ),
            labels={
                "node.kubernetes.io/role": "worker",
            },
            tags={
                "kubernetes.io/cluster/" + self.cluster_name: "owned",
            }
        )

        # Add dependencies
        node_group.add_dependency(self.eks_cluster)
        node_group.add_dependency(launch_template)
        # node_group.add_dependency(self.pod_identity_association)

        return node_group

    def _create_vpc_cni_addon(self) -> eks.CfnAddon:
        """Create Amazon VPC CNI addon."""

        self.vpc_cni_role = self._create_vpc_cni_role()

        addon = eks.CfnAddon(
            self, "VpcCniAddon",
            addon_name="vpc-cni",
            cluster_name=self.eks_cluster.name,
            addon_version="v1.19.2-eksbuild.1",
            resolve_conflicts="OVERWRITE",
            pod_identity_associations=[
                eks.CfnAddon.PodIdentityAssociationProperty(
                    # namespace="kube-system",
                    service_account="aws-node",
                    role_arn=self.vpc_cni_role.get_att("Arn").to_string()
                )
            ],
            configuration_values='{"init": {"env": {"DISABLE_TCP_EARLY_DEMUX": "true"}}, "env": {"POD_SECURITY_GROUP_ENFORCING_MODE": "standard","ENABLE_POD_ENI": "true"}}'
            # configuration_values='{"init": {"env": {"DISABLE_TCP_EARLY_DEMUX": "true"}}, "env": {"AWS_VPC_K8S_CNI_EXTERNALSNAT": "true","POD_SECURITY_GROUP_ENFORCING_MODE": "standard","ENABLE_POD_ENI": "true", "AWS_VPC_K8S_CNI_CUSTOM_NETWORK_CFG": "true"}}'
        )

        # Add dependency on cluster
        addon.add_dependency(self.eks_cluster)
        addon.add_dependency(self.pod_identity_agent_addon)

        return addon

    def _create_kube_proxy_addon(self) -> eks.CfnAddon:
        """Create kube-proxy addon."""
        addon = eks.CfnAddon(
            self, "KubeProxyAddon",
            addon_name="kube-proxy",
            cluster_name=self.eks_cluster.name,
            addon_version="v1.32.0-eksbuild.2",
            resolve_conflicts="OVERWRITE"
        )

        # Add dependency on cluster
        addon.add_dependency(self.eks_cluster)

        return addon

    def _create_coredns_addon(self) -> eks.CfnAddon:
        """Create CoreDNS addon."""
        addon = eks.CfnAddon(
            self, "CoreDnsAddon",
            addon_name="coredns",
            cluster_name=self.eks_cluster.name,
            addon_version="v1.11.4-eksbuild.2",
            resolve_conflicts="OVERWRITE",
            configuration_values='{"replicaCount":2,"resources":{"limits":{"memory":"170Mi"},"requests":{"cpu":"100m","memory":"70Mi"}}}'
        )

        # Add dependency on cluster
        addon.add_dependency(self.node_group)

        return addon

    def _create_pod_identity_agent_addon(self) -> eks.CfnAddon:
        """Create Pod Identity Agent addon."""
        addon = eks.CfnAddon(
            self, "PodIdentityAgentAddon",
            addon_name="eks-pod-identity-agent",
            cluster_name=self.eks_cluster.name,
            addon_version="v1.3.7-eksbuild.2",
            resolve_conflicts="OVERWRITE"
        )

        # Add dependency on cluster
        addon.add_dependency(self.eks_cluster)

        return addon

    def _create_cloudwatch_observability_addon(self) -> eks.CfnAddon:
        """Create CloudWatch Observability addon."""
        self.cloudwatch_observability_role = self._create_cloudwatch_observability_role()

        addon = eks.CfnAddon(
            self, "CloudWatchObservabilityAddon",
            addon_name="amazon-cloudwatch-observability",
            cluster_name=self.eks_cluster.name,
            addon_version="v4.4.0-eksbuild.1",
            resolve_conflicts="OVERWRITE",
            pod_identity_associations=[
                eks.CfnAddon.PodIdentityAssociationProperty(
                    # namespace="external-dns",
                    service_account="cloudwatch-agent",
                    role_arn=self.cloudwatch_observability_role.get_att("Arn").to_string()
                )
            ],
        )

        # Add dependency on cluster
        addon.add_dependency(self.eks_cluster)
        addon.add_dependency(self.pod_identity_agent_addon)

        return addon

    def _create_metrics_server_addon(self) -> eks.CfnAddon:
        """Create Metrics Server addon."""
        addon = eks.CfnAddon(
            self, "MetricsServerAddon",
            addon_name="metrics-server",
            cluster_name=self.eks_cluster.name,
            addon_version="v0.8.0-eksbuild.1",
            resolve_conflicts="OVERWRITE"
        )

        # Add dependency on cluster
        addon.add_dependency(self.node_group)

        return addon

    def _create_external_dns_addon(self) -> eks.CfnAddon:
        """Create External DNS addon."""
        self.external_dns_role = self._create_external_dns_role()
        addon = eks.CfnAddon(
            self, "ExternalDnsAddon",
            addon_name="external-dns",
            cluster_name=self.eks_cluster.name,
            addon_version="v0.18.0-eksbuild.1",
            resolve_conflicts="OVERWRITE",
            pod_identity_associations=[
                eks.CfnAddon.PodIdentityAssociationProperty(
                    # namespace="external-dns",
                    service_account="external-dns",
                    role_arn=self.external_dns_role.get_att("Arn").to_string()
                )
            ],
            configuration_values='{"policy":"sync"}'
        )

        # Add dependency on cluster
        addon.add_dependency(self.node_group)
        addon.add_dependency(self.pod_identity_agent_addon)

        return addon

    def _add_security_group_ingress(self):
        """Add security group ingress to the cluster."""

        ingress_1 = ec2.CfnSecurityGroupIngress(
            self, "EksClusterToWorkloadIngress",
            group_id=self.eks_cluster.get_att("ClusterSecurityGroupId").to_string(),
            from_port=0,
            to_port=65535,
            ip_protocol="-1",
            source_security_group_id=self.eks_workload_sg.security_group_id,
            description="Allow all traffic between EKS cluster and workload pods"
        )

        ingress_2 = ec2.CfnSecurityGroupIngress(
            self, "WorkloadToEksClusterIngress",
            group_id=self.eks_workload_sg.security_group_id,
            from_port=0,
            to_port=65535,
            ip_protocol="-1",
            source_security_group_id=self.eks_cluster.get_att("ClusterSecurityGroupId").to_string(),
            description="Allow all traffic between EKS cluster and workload pods"
        )

        ingress_3 = ec2.CfnSecurityGroupIngress(
            self, "EksClusterToFastApiIngress",
            group_id=self.eks_cluster.get_att("ClusterSecurityGroupId").to_string(),
            from_port=0,
            to_port=65535,
            ip_protocol="-1",
            source_security_group_id=self.eks_fastapi_sg.security_group_id,
            description="Allow all traffic between EKS cluster and fastapi pods"
        )

        ingress_4 = ec2.CfnSecurityGroupIngress(
            self, "EksClusterToAlbIngress",
            group_id=self.eks_cluster.get_att("ClusterSecurityGroupId").to_string(),
            from_port=8080,
            to_port=8080,
            ip_protocol="tcp",
            source_security_group_id=self.alb_security_group.security_group_id,
            description="Allow alb to access argocd pods"
        )

        ingress_1.node.add_dependency(self.eks_cluster)
        ingress_2.node.add_dependency(self.eks_cluster)
        ingress_3.node.add_dependency(self.eks_cluster)
        ingress_4.node.add_dependency(self.eks_cluster)

    def _create_outputs(self):
        """Create CloudFormation outputs for GitOps integration."""

        CfnOutput(
            self, "ClusterName",
            value=self.eks_cluster.name,
            description="EKS Cluster Name",
            export_name=self.config.prefix("cluster-name")
        )

        CfnOutput(
            self, "ClusterEndpoint",
            value=self.eks_cluster.attr_endpoint,
            description="EKS Cluster Endpoint",
            export_name=self.config.prefix("cluster-endpoint")
        )

        CfnOutput(
            self, "ClusterArn",
            value=self.eks_cluster.attr_arn,
            description="EKS Cluster ARN",
            export_name=self.config.prefix("cluster-arn")
        )

        CfnOutput(
            self, "NodeRoleArn",
            value=self.node_role.role_arn,
            description="EKS Node Role ARN",
            export_name=self.config.prefix("node-role-arn")
        )

        CfnOutput(
            self, "KarpenterNodeRoleArn",
            value=self.karpenter_node_role.role_arn,
            description="Karpenter Node Role ARN",
            export_name=self.config.prefix("karpenter-node-role-arn")
        )

        CfnOutput(
            self, "KarpenterControllerRoleArn",
            value=self.karpenter_controller_role.get_att("Arn").to_string(),
            description="Karpenter Controller Role ARN",
            export_name=self.config.prefix("karpenter-controller-role-arn")
        )

        CfnOutput(
            self, "AlbControllerRoleArn",
            value=self.alb_controller_role.get_att("Arn").to_string(),
            description="ALB Controller Role ARN",
            export_name=self.config.prefix("alb-controller-role-arn")
        )
