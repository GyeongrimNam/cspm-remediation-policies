#2단계 manual 부분을 runbook.yml 로 만들기

from pathlib import Path
import re
import yaml


INPUT_YML = Path("generated/unmapped_candidates.yml")
OUTPUT_YML = Path("runbook.yml")


def parse_console_steps(text):
    """
    Prowler의 console 문자열:
      1. ...
      2. ...
      3. ...

    을 YAML list로 변환한다.
    """

    if not text:
        return []

    text = str(text).strip()

    parts = re.split(r"(?:^|\n)\s*\d+\.\s+", text)

    return [
        part.strip()
        for part in parts
        if part.strip()
    ]


def main():
    with INPUT_YML.open("r", encoding="utf-8") as f:
        candidates = yaml.safe_load(f) or {}

    runbook = {}

    for check_id, item in candidates.items():

        # manual 항목만 Runbook 생성
        if item.get("mode") != "manual":
            continue

        remediation = item.get("remediation") or {}

        cli = remediation.get("cli")
        console = remediation.get("console")

        # 기본 실행 방법 표시
        if cli and console:
            method = "cli_or_console"
        elif cli:
            method = "cli"
        elif console:
            method = "console"
        else:
            method = "guide"

        runbook[check_id] = {
            "method": method,
            "description": remediation.get("description"),
            "command_template": cli,
            "console_steps": parse_console_steps(console),
            "docs_url": remediation.get("docs_url"),
        }

    with OUTPUT_YML.open("w", encoding="utf-8") as f:
        yaml.safe_dump(
            runbook,
            f,
            allow_unicode=True,
            sort_keys=False,
            default_flow_style=False,
        )

    print(f"Runbook 생성 check 수: {len(runbook)}")
    print(f"출력 파일: {OUTPUT_YML}")


if __name__ == "__main__":
    main()