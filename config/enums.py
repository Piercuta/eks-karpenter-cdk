from enum import Enum


class EnvironmentName(str, Enum):
    """Available environments."""
    DEV = "dev"
    STAGING = "staging"
    PROD = "prod"


class AwsRegion(str, Enum):
    """Available AWS regions."""
    EU_WEST_1 = "eu-west-1"
    EU_WEST_2 = "eu-west-2"
    EU_WEST_3 = "eu-west-3"
    EU_CENTRAL_1 = "eu-central-1"
    US_EAST_1 = "us-east-1"
    US_EAST_2 = "us-east-2"
    US_WEST_1 = "us-west-1"
    US_WEST_2 = "us-west-2"
