"""
EKS Utility Functions

This module contains reusable functions for EKS operations that can be used
across different CDK constructs and stacks.
"""

from aws_cdk import (
    aws_eks as eks,
    CfnTag
)
from typing import List, Optional, Union
from constructs import Construct


def create_access_entry(
    scope: Construct,
    id: str,
    cluster_name: str,
    principal_arn: str,
    access_policies: List[eks.CfnAccessEntry.AccessPolicyProperty],
    access_entry_type: str = "STANDARD",
    cluster_dependency: Optional[eks.CfnCluster] = None
) -> eks.CfnAccessEntry:
    """
    Create an EKS access entry for cluster access control.

    Args:
        scope: The CDK construct scope
        id: Unique identifier for the access entry
        cluster_name: Name of the EKS cluster
        principal_arn: ARN of the principal (user/role) to grant access
        access_policies: List of access policies to apply
        access_entry_type: Type of access entry (STANDARD, FARGATE_LINUX, EC2_LINUX, EC2_WINDOWS)
        cluster_dependency: Optional cluster dependency for proper ordering

    Returns:
        eks.CfnAccessEntry: The created access entry

    Example:
        ```python
        from cdk_constructs.eks_utils import create_access_entry

        # Create admin access entry
        admin_access = create_access_entry(
            scope=self,
            id="AdminAccess",
            cluster_name="my-cluster",
            principal_arn="arn:aws:iam::123456789012:role/AdminRole",
            access_policies=[
                eks.CfnAccessEntry.AccessPolicyProperty(
                    access_scope=eks.CfnAccessEntry.AccessScopeProperty(type="cluster"),
                    policy_arn="arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
                )
            ]
        )
        ```
    """

    access_entry = eks.CfnAccessEntry(
        scope, id,
        cluster_name=cluster_name,
        principal_arn=principal_arn,
        access_policies=access_policies,
        type=access_entry_type
    )

    # Add dependency on cluster if provided
    if cluster_dependency:
        access_entry.node.add_dependency(cluster_dependency)

    return access_entry


def create_pod_identity_association(
    scope: Construct,
    id: str,
    cluster_name: str,
    namespace: str,
    service_account: str,
    role_arn: str,
    tags: Optional[List[CfnTag]] = None,
    pod_identity_agent_dependency: Optional[eks.CfnAddon] = None
) -> eks.CfnPodIdentityAssociation:
    """
    Create a pod identity association for EKS service accounts.

    Args:
        scope: The CDK construct scope
        id: Unique identifier for the pod identity association
        cluster_name: Name of the EKS cluster
        namespace: Kubernetes namespace
        service_account: Kubernetes service account name
        role_arn: ARN of the IAM role to associate
        tags: Optional list of tags to apply
        pod_identity_agent_dependency: Optional pod identity agent addon dependency

    Returns:
        eks.CfnPodIdentityAssociation: The created pod identity association

    Example:
        ```python
        from cdk_constructs.eks_utils import create_pod_identity_association

        # Create pod identity association for Karpenter
        karpenter_association = create_pod_identity_association(
            scope=self,
            id="KarpenterPodIdentity",
            cluster_name="my-cluster",
            namespace="kube-system",
            service_account="karpenter",
            role_arn=karpenter_role.role_arn,
            tags=[
                CfnTag(key="Name", value="karpenter-pod-identity"),
                CfnTag(key="Service", value="karpenter")
            ]
        )
        ```
    """

    # Set default tags if none provided
    if tags is None:
        tags = [
            CfnTag(key="Name", value=f"{service_account}-pod-identity-association"),
        ]

    association = eks.CfnPodIdentityAssociation(
        scope, id,
        cluster_name=cluster_name,
        namespace=namespace,
        role_arn=role_arn,
        service_account=service_account,
        tags=tags
    )

    # Add dependency on pod identity agent if provided
    if pod_identity_agent_dependency:
        association.node.add_dependency(pod_identity_agent_dependency)

    return association


def create_standard_admin_access_entry(
    scope: Construct,
    id: str,
    cluster_name: str,
    principal_arn: str,
    cluster_dependency: Optional[eks.CfnCluster] = None
) -> eks.CfnAccessEntry:
    """
    Create a standard admin access entry with cluster admin policy.

    Args:
        scope: The CDK construct scope
        id: Unique identifier for the access entry
        cluster_name: Name of the EKS cluster
        principal_arn: ARN of the principal (user/role) to grant admin access
        cluster_dependency: Optional cluster dependency for proper ordering

    Returns:
        eks.CfnAccessEntry: The created admin access entry

    Example:
        ```python
        from cdk_constructs.eks_utils import create_standard_admin_access_entry

        # Create admin access for SSO role
        admin_access = create_standard_admin_access_entry(
            scope=self,
            id="SSOAdminAccess",
            cluster_name="my-cluster",
            principal_arn="arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/eu-west-1/AWSReservedSSO_AdministratorAccess_xxx"
        )
        ```
    """

    return create_access_entry(
        scope=scope,
        id=id,
        cluster_name=cluster_name,
        principal_arn=principal_arn,
        access_policies=[
            eks.CfnAccessEntry.AccessPolicyProperty(
                access_scope=eks.CfnAccessEntry.AccessScopeProperty(type="cluster"),
                policy_arn="arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
            )
        ],
        access_entry_type="STANDARD",
        cluster_dependency=cluster_dependency
    )


def create_readonly_access_entry(
    scope: Construct,
    id: str,
    cluster_name: str,
    principal_arn: str,
    cluster_dependency: Optional[eks.CfnCluster] = None
) -> eks.CfnAccessEntry:
    """
    Create a read-only access entry with cluster view policy.

    Args:
        scope: The CDK construct scope
        id: Unique identifier for the access entry
        cluster_name: Name of the EKS cluster
        principal_arn: ARN of the principal (user/role) to grant read-only access
        cluster_dependency: Optional cluster dependency for proper ordering

    Returns:
        eks.CfnAccessEntry: The created read-only access entry

    Example:
        ```python
        from cdk_constructs.eks_utils import create_readonly_access_entry

        # Create read-only access for monitoring role
        readonly_access = create_readonly_access_entry(
            scope=self,
            id="MonitoringAccess",
            cluster_name="my-cluster",
            principal_arn="arn:aws:iam::123456789012:role/MonitoringRole"
        )
        ```
    """

    return create_access_entry(
        scope=scope,
        id=id,
        cluster_name=cluster_name,
        principal_arn=principal_arn,
        access_policies=[
            eks.CfnAccessEntry.AccessPolicyProperty(
                access_scope=eks.CfnAccessEntry.AccessScopeProperty(type="cluster"),
                policy_arn="arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterViewPolicy"
            )
        ],
        access_entry_type="STANDARD",
        cluster_dependency=cluster_dependency
    )


def create_namespace_access_entry(
    scope: Construct,
    id: str,
    cluster_name: str,
    principal_arn: str,
    namespace: str,
    policy_arn: str = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy",
    cluster_dependency: Optional[eks.CfnCluster] = None
) -> eks.CfnAccessEntry:
    """
    Create a namespace-scoped access entry.

    Args:
        scope: The CDK construct scope
        id: Unique identifier for the access entry
        cluster_name: Name of the EKS cluster
        principal_arn: ARN of the principal (user/role) to grant access
        namespace: Kubernetes namespace to scope access to
        policy_arn: ARN of the access policy to apply
        cluster_dependency: Optional cluster dependency for proper ordering

    Returns:
        eks.CfnAccessEntry: The created namespace-scoped access entry

    Example:
        ```python
        from cdk_constructs.eks_utils import create_namespace_access_entry

        # Create namespace-scoped access for development team
        dev_access = create_namespace_access_entry(
            scope=self,
            id="DevTeamAccess",
            cluster_name="my-cluster",
            principal_arn="arn:aws:iam::123456789012:role/DevTeamRole",
            namespace="development"
        )
        ```
    """

    return create_access_entry(
        scope=scope,
        id=id,
        cluster_name=cluster_name,
        principal_arn=principal_arn,
        access_policies=[
            eks.CfnAccessEntry.AccessPolicyProperty(
                access_scope=eks.CfnAccessEntry.AccessScopeProperty(
                    type="namespace",
                    namespaces=[namespace]
                ),
                policy_arn=policy_arn
            )
        ],
        access_entry_type="STANDARD",
        cluster_dependency=cluster_dependency
    )
