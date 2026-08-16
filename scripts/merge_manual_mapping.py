from pathlib import Path
import yaml

MANUAL_YML = Path("generated/unmapped_candidates.yml")
MAPPING_YML = Path("mapping.yml")


def main():
    with MAPPING_YML.open("r", encoding="utf-8") as f:
        mapping = yaml.safe_load(f) or {}

    with MANUAL_YML.open("r", encoding="utf-8") as f:
        candidates = yaml.safe_load(f) or {}

    added = 0
    skipped = 0

    for check_id, item in candidates.items():
        if item.get("mode") != "manual":
            continue

        # 기존 approve 항목 보호
        if check_id in mapping:
            skipped += 1
            continue

        mapping[check_id] = {
            "policy": None,
            "mode": "manual",
            "runbook": check_id,
            "auto_eligible": False,
            "scope_key": None,
        }

        added += 1

    with MAPPING_YML.open("w", encoding="utf-8") as f:
        yaml.safe_dump(
            mapping,
            f,
            allow_unicode=True,
            sort_keys=False
        )

    print(f"manual 추가: {added}")
    print(f"기존 mapping skip: {skipped}")
    print(f"최종 mapping 수: {len(mapping)}")


if __name__ == "__main__":
    main()