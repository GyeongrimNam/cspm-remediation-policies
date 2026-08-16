# 2단계: manual 부분을 runbook.yml로 만들기

from pathlib import Path
import re
import yaml


INPUT_YML = Path("generated/unmapped_candidates.yml")
OUTPUT_YML = Path("runbook.yml")


# ------------------------------------------------------------
# YAML에서 긴 문자열을 >- 형태로 출력하기 위한 설정
# ------------------------------------------------------------

class FoldedString(str):
    pass


class PrettyDumper(yaml.SafeDumper):
    pass


def folded_string_representer(dumper, data):
    return dumper.represent_scalar(
        "tag:yaml.org,2002:str",
        data,
        style=">"
    )


PrettyDumper.add_representer(
    FoldedString,
    folded_string_representer
)


# ------------------------------------------------------------
# description 정리
# ------------------------------------------------------------

def clean_text(text):
    if not text:
        return None

    text = str(text).strip()

    # 연속된 빈 줄 제거
    text = re.sub(r"\n\s*\n+", "\n", text)

    return text


# ------------------------------------------------------------
# Prowler console 문자열을 step list로 변환
# ------------------------------------------------------------

def parse_console_steps(text):
    if not text:
        return []

    text = str(text).strip()

    parts = re.split(
        r"(?:^|\n)\s*\d+\.\s+",
        text
    )

    return [
        re.sub(r"\s+", " ", part).strip()
        for part in parts
        if part.strip()
    ]


# ------------------------------------------------------------
# AWS CLI 명령어 가독성 개선
# ------------------------------------------------------------

def format_command(command):
    if not command:
        return None

    command = str(command).strip()

    # --옵션 앞에서 줄바꿈
    command = re.sub(
        r"\s+(--[a-zA-Z0-9-]+)",
        r"\n\1",
        command
    )

    return FoldedString(command)


# ------------------------------------------------------------
# YAML 출력 가독성 개선
# ------------------------------------------------------------

def pretty_yaml(runbook):
    yaml_text = yaml.dump(
        runbook,
        Dumper=PrettyDumper,
        allow_unicode=True,
        sort_keys=False,
        default_flow_style=False,
        width=120,
    )

    lines = yaml_text.splitlines()
    pretty_lines = []

    # 이 필드 앞에는 빈 줄 하나 추가
    separate_fields = {
        "description",
        "command_template",
        "console_steps",
        "docs_url",
    }

    for line in lines:

        # ----------------------------------------------------
        # 새로운 check_id 시작
        # check_id 사이에는 빈 줄 2개
        # ----------------------------------------------------
        if line and not line.startswith(" "):

            if pretty_lines:
                while pretty_lines and pretty_lines[-1] == "":
                    pretty_lines.pop()

                pretty_lines.append("")
                pretty_lines.append("")

        # ----------------------------------------------------
        # 필드 사이에는 빈 줄 1개
        # ----------------------------------------------------
        elif line.startswith("  ") and not line.startswith("    "):

            field_name = line.strip().split(":", 1)[0]

            if field_name in separate_fields:
                if pretty_lines and pretty_lines[-1] != "":
                    pretty_lines.append("")

        pretty_lines.append(line)

    return "\n".join(pretty_lines) + "\n"


# ------------------------------------------------------------
# Main
# ------------------------------------------------------------

def main():

    # manual 후보 읽기
    with INPUT_YML.open("r", encoding="utf-8") as f:
        candidates = yaml.safe_load(f) or {}

    runbook = {}

    # --------------------------------------------------------
    # manual 항목만 runbook 생성
    # --------------------------------------------------------

    for check_id, item in candidates.items():

        if item.get("mode") != "manual":
            continue

        remediation = item.get("remediation") or {}

        description = clean_text(
            remediation.get("description")
        )

        cli = remediation.get("cli")
        console = remediation.get("console")

        # ----------------------------------------------------
        # 지원되는 조치 방식 판정
        # ----------------------------------------------------

        if cli and console:
            method = "cli_or_console"

        elif cli:
            method = "cli"

        elif console:
            method = "console"

        else:
            method = "guide"

        # ----------------------------------------------------
        # runbook 항목 생성
        # ----------------------------------------------------

        runbook[check_id] = {
            "method": method,

            "description": (
                FoldedString(description)
                if description
                else None
            ),

            "command_template": format_command(cli),

            "console_steps": parse_console_steps(console),

            "docs_url": remediation.get("docs_url"),
        }

    # --------------------------------------------------------
    # YAML 생성 + 보기 좋게 정리
    # --------------------------------------------------------

    output_text = pretty_yaml(runbook)

    with OUTPUT_YML.open("w", encoding="utf-8") as f:
        f.write(output_text)

    print(f"Runbook 생성 check 수: {len(runbook)}")
    print(f"출력 파일: {OUTPUT_YML}")


if __name__ == "__main__":
    main()