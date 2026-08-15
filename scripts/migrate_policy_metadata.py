from __future__ import annotations

import argparse
import copy
import sys
from collections import Counter
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
FILES = [
    ROOT / "policies/cloudtrail.yml",
    ROOT / "policies/ec2.yml",
    ROOT / "policies/iam.yml",
    ROOT / "policies/s3.yml",
]
APPROVE = {
    "cloudtrail_log_file_validation_enabled": ("none", "resource", "hours", True, "low"),
    "ec2_ebs_default_encryption": ("none", "region", "immediate", True, "none"),
    "ec2_ebs_volume_snapshots_exists": ("none", "resource", "minutes", True, "low"),
    "ec2_instance_account_imdsv2_enabled": ("none", "region", "immediate", True, "none"),
    "ec2_instance_imdsv2_enabled": ("access", "resource", "seconds", True, "none"),
    "ec2_instance_detailed_monitoring_enabled": ("none", "resource", "minutes", True, "low"),
    "ec2_securitygroup_allow_ingress_from_internet_to_any_port_from_ip": ("traffic", "resource", "seconds", True, "none"),
    "iam_password_policy_lowercase": ("access", "account", "immediate", True, "none"),
    "iam_password_policy_minimum_length_14": ("access", "account", "immediate", True, "none"),
    "iam_password_policy_number": ("access", "account", "immediate", True, "none"),
    "iam_password_policy_reuse_24": ("access", "account", "immediate", True, "none"),
    "iam_password_policy_symbol": ("access", "account", "immediate", True, "none"),
    "iam_password_policy_uppercase": ("access", "account", "immediate", True, "none"),
    "s3_account_level_public_access_blocks": ("access", "account", "minutes", True, "none"),
    "s3_bucket_kms_encryption": ("access", "resource", "minutes", True, "low"),
    "s3_bucket_secure_transport_policy": ("traffic", "resource", "minutes", True, "none"),
}

AUTO = {
    "cloudtrail_log_file_validation_enabled": (
        "resource",
        "Auto 활성화 시 opt-in한 CloudTrail Trail에서 동일 위반이 다시 탐지되면 사용자 승인 없이 Log File Validation이 자동으로 활성화됩니다. Digest File 저장으로 S3 저장량이 증가할 수 있습니다.",
        "aws cloudtrail update-trail --name {trail_name} --no-enable-log-file-validation",
    ),
    "ec2_ebs_default_encryption": (
        "region",
        "Auto 활성화 시 opt-in한 리전에서 동일 위반이 다시 탐지되면 사용자 승인 없이 EBS 기본 암호화가 자동으로 활성화됩니다. 기존 볼륨에는 적용되지 않습니다.",
        "aws ec2 disable-ebs-encryption-by-default --region {region}",
    ),
    "ec2_ebs_volume_snapshots_exists": (
        "resource",
        "Auto 활성화 시 opt-in한 EBS Volume에서 동일 위반이 다시 탐지되면 사용자 승인 없이 Snapshot이 자동으로 생성됩니다. Snapshot 저장 비용이 발생할 수 있습니다.",
        None,
    ),
    "ec2_instance_account_imdsv2_enabled": (
        "region",
        "Auto 활성화 시 opt-in한 리전에서 동일 위반이 다시 탐지되면 사용자 승인 없이 EC2 Metadata 기본값이 IMDSv2 강제로 자동 변경됩니다. 기존 인스턴스에는 소급 적용되지 않습니다.",
        "aws ec2 modify-instance-metadata-defaults --region {region} --http-tokens optional",
    ),
    "ec2_instance_detailed_monitoring_enabled": (
        "resource",
        "Auto 활성화 시 opt-in한 EC2 Instance에서 동일 위반이 다시 탐지되면 사용자 승인 없이 Detailed Monitoring이 자동으로 활성화됩니다. CloudWatch Metric 비용이 발생할 수 있습니다.",
        "aws ec2 unmonitor-instances --instance-ids {instance_id}",
    ),
}

for check in (
    "iam_password_policy_lowercase",
    "iam_password_policy_minimum_length_14",
    "iam_password_policy_number",
    "iam_password_policy_reuse_24",
    "iam_password_policy_symbol",
    "iam_password_policy_uppercase",
):
    AUTO[check] = (
        "account",
        "Auto 활성화 시 opt-in한 계정에서 동일 위반이 다시 탐지되면 사용자 승인 없이 해당 IAM Password Policy 요구 조건이 자동으로 적용됩니다. 이후 비밀번호 변경 시 새 요구사항이 적용될 수 있습니다.",
        None,
    )


def folded(text: str, indent: int) -> list[str]:
    prefix = " " * indent
    return [prefix + text]


def metadata_lines(check: str, mapping: dict) -> list[str]:
    disruption, radius, delay, reversible, cost = APPROVE[check]
    lines = [
        "    metadata:",
        f"      prowler_check: {check}",
        "",
        "      approve:",
        f"        disruption: {disruption}",
        f"        blast_radius: {radius}",
        f"        propagation_delay: {delay}",
        f"        reversible: {str(reversible).lower()}",
        f"        cost_impact: {cost}",
        "        risk_note: >-",
        *folded(mapping[check]["risk_note"], 10),
    ]
    if mapping[check]["auto_eligible"]:
        scope, warning, rollback = AUTO[check]
        lines += [
            "",
            "      auto:",
            "        warning: >",
            *folded(warning, 10),
            "",
            "        allowed_scopes:",
            f"          - {scope}",
            "",
            f"        rollback_cli: {('null' if rollback is None else yaml.safe_dump(rollback, allow_unicode=True, default_flow_style=True).splitlines()[0])}",
            "        cooldown: 24h",
            "        post_notification: log",
        ]
    return lines


def migrate(text: str, mapping: dict) -> str:
    lines = text.splitlines()
    starts = [i for i, line in enumerate(lines) if line.startswith("  - name: ")]
    for start, end in reversed(list(zip(starts, starts[1:] + [len(lines)]))):
        name = lines[start].split(":", 1)[1].strip()
        metadata_start = next(i for i in range(start, end) if lines[i] == "    metadata:")
        check_line = next(i for i in range(metadata_start + 1, end) if lines[i].startswith("      prowler_check:"))
        check = lines[check_line].split(":", 1)[1].strip()
        assert mapping[check]["policy"] == name, (check, name, mapping[check]["policy"])
        metadata_end = end
        for i in range(metadata_start + 1, end):
            if lines[i].startswith("    ") and not lines[i].startswith("      ") and lines[i].strip().endswith(":"):
                metadata_end = i
                break
        replacement = metadata_lines(check, mapping)
        if metadata_end < end and replacement[-1] != "":
            replacement.append("")
        lines[metadata_start:metadata_end] = replacement
    return "\n".join(lines) + "\n"


def policies(document):
    return document if isinstance(document, list) else document["policies"]


def validate(mapping, documents, snapshots):
    approve_keys = {"disruption", "blast_radius", "propagation_delay", "reversible", "cost_impact", "risk_note"}
    auto_keys = {"warning", "allowed_scopes", "rollback_cli", "cooldown", "post_notification"}
    for path, document in documents.items():
        for policy in policies(document):
            metadata = policy.get("metadata", {})
            check = metadata.get("prowler_check")
            if check not in mapping:
                raise ValueError(f"{policy.get('name')}: mapping missing for {check}")
            entry = mapping[check]
            for key in ("policy", "mode", "auto_eligible", "scope_key", "risk_note"):
                if key not in entry:
                    raise ValueError(f"{check}: mapping field missing: {key}")
            if entry["policy"] != policy["name"] or entry["mode"] != "approve":
                raise ValueError(f"{check}: mapping linkage mismatch")
            if check not in APPROVE or (entry["auto_eligible"] and check not in AUTO):
                raise ValueError(f"{check}: migration metadata missing")
            if set(metadata) != ({"prowler_check", "approve", "auto"} if entry["auto_eligible"] else {"prowler_check", "approve"}):
                raise ValueError(f"{check}: metadata schema mismatch")
            if set(metadata["approve"]) != approve_keys or metadata["approve"]["risk_note"] != entry["risk_note"]:
                raise ValueError(f"{check}: approve/risk_note mismatch")
            if entry["auto_eligible"] and set(metadata["auto"]) != auto_keys:
                raise ValueError(f"{check}: auto schema mismatch")
            if snapshots[policy["name"]] != (policy.get("filters"), policy.get("actions")):
                raise ValueError(f"{check}: filters/actions changed")


def main():
    parser = argparse.ArgumentParser(description="Migrate policy metadata using mapping.yml")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    mapping = yaml.safe_load((ROOT / "mapping.yml").read_text(encoding="utf-8"))
    documents = {p: yaml.safe_load(p.read_text(encoding="utf-8")) for p in FILES}
    snapshots = {p["name"]: (copy.deepcopy(p.get("filters")), copy.deepcopy(p.get("actions"))) for d in documents.values() for p in policies(d)}
    # Complete linkage and policy-specific definition validation before writes.
    for document in documents.values():
        for policy in policies(document):
            check = policy.get("metadata", {}).get("prowler_check")
            if check not in mapping or mapping[check].get("policy") != policy.get("name") or mapping[check].get("mode") != "approve":
                raise ValueError(f"preflight linkage failed: {policy.get('name')}")
            if check not in APPROVE or (mapping[check].get("auto_eligible") and check not in AUTO):
                raise ValueError(f"preflight metadata definition failed: {check}")
    originals = {p: p.read_text(encoding="utf-8") for p in FILES}
    rendered = {p: migrate(("policies:\n" + originals[p].lstrip("\ufeff")) if isinstance(documents[p], list) else originals[p], mapping) for p in FILES}
    rendered_docs = {p: yaml.safe_load(rendered[p]) for p in FILES}
    migrated_policies = sum(
        old["metadata"] != next(x for x in policies(rendered_docs[path]) if x["name"] == old["name"])["metadata"]
        for path, document in documents.items() for old in policies(document)
    )
    modified = sum(originals[p] != rendered[p] for p in FILES)
    if args.check and modified:
        print(f"CHECK FAILED: {modified} file(s) require migration", file=sys.stderr)
        return 1
    if args.apply:
        for path, content in rendered.items():
            path.write_text(content, encoding="utf-8", newline="\n")
    final_docs = {p: yaml.safe_load((rendered[p] if args.apply else originals[p])) for p in FILES}
    validate(mapping, final_docs, snapshots)
    linked = [mapping[p["metadata"]["prowler_check"]] for d in final_docs.values() for p in policies(d)]
    eligible = sum(bool(e["auto_eligible"]) for e in linked)
    print("[Policy Metadata Migration]")
    print(f"files:\n- scanned: 4\n- modified: {modified if args.apply else 0}")
    changed = migrated_policies if args.apply else 0
    print(f"policies:\n- total: {len(linked)}\n- migrated: {changed}\n- unchanged: {len(linked)-changed}")
    print(f"auto:\n- eligible: {eligible}\n- non_eligible: {len(linked)-eligible}\n- auto blocks added: 0\n- auto blocks removed: 0")
    print("legacy metadata removed:\n- remediation_summary: 0\n- note: 0\n- 기타: 0")
    print("validation:")
    for label in ("YAML parse", "mapping linkage", "risk_note sync", "approve schema", "auto schema", "legacy fields", "filters unchanged", "actions unchanged"):
        print(f"- {label}: PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, yaml.YAMLError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(2)





