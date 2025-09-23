import os
import yaml
from pathlib import Path


def substitute_env_variables(data):
    """Substitute environment variables in YAML data recursively with proper types."""
    if isinstance(data, dict):
        return {key: substitute_env_variables(value) for key, value in data.items()}
    elif isinstance(data, list):
        return [substitute_env_variables(item) for item in data]
    elif isinstance(data, str):
        expanded = os.path.expandvars(data)
        if expanded.isdigit():
            return int(expanded)
        return expanded
    else:
        return data


# Récupère tous les sous-dossiers (uniquement dossiers, pas la racine)
root_path = Path.cwd()

for subdir in root_path.iterdir():
    if not subdir.is_dir():
        continue

    for yaml_path in subdir.rglob("*.yaml"):
        try:
            with open(yaml_path, "r") as f:
                data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            print(f"⚠️ Failed to parse {yaml_path}: {e}")
            continue

        if data is None:
            print(f"Skipping empty file {yaml_path}")
            continue

        new_data = substitute_env_variables(data)

        with open(yaml_path, "w") as f:
            yaml.dump(new_data, f, default_flow_style=False)

        print(f"✔️ Replaced variables in {yaml_path}")
