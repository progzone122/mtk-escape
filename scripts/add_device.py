import json
import argparse
import os
from typing import Any, Dict, Optional


def load_json(path: str) -> Dict[str, Any]:
    if not os.path.exists(path):
        return {"devices": {}}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_json(data: Dict[str, Any], path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def add_device(
    config_path: str,
    vendor: str,
    codename: str,
    name: str,
    da_path: Optional[str] = None,
    carbonara: bool = False,
    only_stage1: bool = False,
    auth_file: Optional[str] = None,
) -> None:
    data = load_json(config_path)
    vendor_data = data.setdefault("devices", {}).setdefault(vendor, {})

    # Get existing device or create a new one
    device_entry = vendor_data.get(codename, {"name": name, "da_files": None, "auth_file": None})
    device_entry["name"] = name
    device_entry["auth_file"] = auth_file if auth_file else None

    # Update or add DA file
    if da_path:
        da_list = device_entry.get("da_files") or []
        for da in da_list:
            if da["path"] == da_path:
                da["flags"]["carbonara"] = carbonara
                da["flags"]["only_stage1"] = only_stage1
                break
        else:
            da_list.append({
                "path": da_path,
                "flags": {"carbonara": carbonara, "only_stage1": only_stage1}
            })
        device_entry["da_files"] = da_list

    vendor_data[codename] = device_entry
    save_json(data, config_path)
    print(f"[OK] Device '{codename}' for vendor '{vendor}' has been added/updated.")


def main():
    parser = argparse.ArgumentParser(description="Add or update a device in JSON config")
    parser.add_argument("--config", "-c", default="repo.json", help="Path to JSON config file")
    parser.add_argument("--vendor", "-v", required=True, help="Vendor name (e.g., motorola, huawei)")
    parser.add_argument("--codename", "-d", required=True, help="Device codename")
    parser.add_argument("--name", "-n", required=True, help="Device display name")
    parser.add_argument("--auth_file", "-a", help="Path to auth file (optional)")
    parser.add_argument("--da", "-f", help="Path to DA file (optional)")
    parser.add_argument("--carbonara", action="store_true", help="Carbonara flag for the DA file")
    parser.add_argument("--only_stage1", action="store_true", help="Only_stage1 flag for the DA file")

    args = parser.parse_args()

    if args.da and not os.path.isfile(args.da):
        raise FileNotFoundError(f"DA file not found: {args.da}")
    if args.auth_file and not os.path.isfile(args.auth_file):
        raise FileNotFoundError(f"Auth file not found: {args.auth_file}")

    add_device(
        args.config,
        args.vendor,
        args.codename,
        args.name,
        da_path=args.da,
        carbonara=args.carbonara,
        only_stage1=args.only_stage1,
        auth_file=args.auth_file,
    )


if __name__ == "__main__":
    main()
