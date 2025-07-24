"""
CDK Constructs Package

This package contains reusable CDK constructs for AWS infrastructure.
"""

# Import EKS utility functions for easy access
from .eks_utils import (
    create_access_entry,
    create_pod_identity_association,
    create_standard_admin_access_entry,
    create_readonly_access_entry,
    create_namespace_access_entry
)

__all__ = [
    'create_access_entry',
    'create_pod_identity_association',
    'create_standard_admin_access_entry',
    'create_readonly_access_entry',
    'create_namespace_access_entry'
]
