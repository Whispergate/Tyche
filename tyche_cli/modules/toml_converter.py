import json
import tomllib
from pathlib import Path
from typing import Any


class TOMLConverter:
    @staticmethod
    def toml_to_json(toml_content: str) -> str:
        data = tomllib.loads(toml_content)
        return json.dumps(data, indent=2)

    @staticmethod
    def toml_file_to_json_file(toml_path: Path, json_path: Path) -> None:
        with open(toml_path, 'rb') as f:
            data = tomllib.load(f)

        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)

    @staticmethod
    def dict_to_json(data: dict[str, Any]) -> str:
        return json.dumps(data, indent=2)

    @staticmethod
    def load_toml_file(toml_path: Path) -> dict[str, Any]:
        with open(toml_path, 'rb') as f:
            return tomllib.load(f)


def convert_toml_to_json(input_path: str, output_path: str) -> None:
    input_file = Path(input_path)
    output_file = Path(output_path)

    if not input_file.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")

    TOMLConverter.toml_file_to_json_file(input_file, output_file)
