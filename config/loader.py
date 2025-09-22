# config/loader.py
import yaml
import json
import os
from typing import Dict, Any
from aws_cdk import App
from .base_config import InfrastructureConfig, AwsConfig, VpcConfig, DatabaseConfig, EksConfig, FrontendConfig, DnsConfig, CICDFrontendConfig, CICDK8SMainAPIConfig, CICDK8SFileServiceConfig, MediaStorageConfig


class ConfigLoader:
    def __init__(self, env_name: str, project_name: str):
        self.env_name = env_name
        self.project_name = project_name
        self.base_path = os.path.dirname(os.path.abspath(__file__))

    def load_environment_config(self) -> Dict[str, Any]:
        """Charge the configuration from the YAML file."""
        config_path = os.path.join(self.base_path, 'environments', f'{self.env_name}.yaml')
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)

    # useless for now
    def load_secrets(self) -> Dict[str, Any]:
        """Charge the secrets from the JSON file."""
        secrets_path = os.path.join(self.base_path, 'secrets', f'{self.env_name}.json')
        with open(secrets_path, 'r') as f:
            return json.load(f)

    def create_config(self) -> InfrastructureConfig:
        """Create the complete configuration."""
        env_config = self.load_environment_config()
        # secrets = self.load_secrets()

        # Merge configuration and secrets
        config = {
            'env_name': self.env_name,
            'project_name': self.project_name,
            'aws': AwsConfig(**env_config['aws']),
            'vpc': VpcConfig(**env_config['vpc']),
            'eks': EksConfig(**env_config['eks']),
            'database': DatabaseConfig(**env_config['database']),
            'cicd_k8s_main_api': CICDK8SMainAPIConfig(**env_config['cicd_k8s_main_api']),
            'cicd_k8s_file_service': CICDK8SFileServiceConfig(**env_config['cicd_k8s_file_service']),
            'frontend': FrontendConfig(**env_config['frontend']),
            'media_storage': MediaStorageConfig(**env_config['media_storage']),
            'cicd_frontend': CICDFrontendConfig(**env_config['cicd_frontend']),
            'dns': DnsConfig(**env_config['dns'])
        }

        return InfrastructureConfig(**config)
