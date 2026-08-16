# 1차 가공 
# approve 를 제외한 manual에 해당하는 check_id 를 골라내기 위한 코드

import csv
from pathlib import Path

import yaml


# ============================================================
# 경로 설정
# ============================================================

INPUT_CSV = Path(
    "inputs/prowler-output-196338354352-20260815140410.csv"
)

MAPPING_YML = Path("mapping.yml")

OUTPUT_YML = Path("generated/non_approve_candidates.yml")


# ============================================================
# 공통 함수
# ============================================================

def clean(value):
    if value is None:
        return ""

    return value.strip()


# ============================================================
# mapping.yml 읽기
# ============================================================

def load_existing_mapping(mapping_path):
    """
    현재 mapping.yml에 이미 등록되어 있는 check_id를 읽는다.

    이미 approve 정책으로 작업한 check_id들은
    이후 후보 목록에서 제외하기 위함.
    """

    if not mapping_path.exists():
        return set()

    with mapping_path.open(
        "r",
        encoding="utf-8"
    ) as f:
        data = yaml.safe_load(f) or {}

    # mapping.yml이 아래처럼 생긴 경우
    #
    # ec2_ebs_default_encryption:
    #   policy: ec2-ebs-default-encryption
    #   mode: approve
    #
    # check_id가 top-level key이므로 그대로 사용
    return set(data.keys())


# ============================================================
# CSV에서 미매핑 FAIL check 추출
# ============================================================

def extract_candidates(csv_path, existing_check_ids):
    """
    Prowler CSV에서:

    1. FAIL만 선택
    2. 이미 mapping.yml에 있는 check_id 제외
    3. CHECK_ID 기준 중복 제거
    4. remediation 정보 추출
    """

    candidates = {}

    with csv_path.open(
        "r",
        encoding="utf-8-sig",
        newline=""
    ) as f:

        reader = csv.DictReader(
            f,
            delimiter=";"
        )

        for row in reader:

            # ------------------------------------------------
            # 1. FAIL만 사용
            # ------------------------------------------------

            status = clean(row.get("STATUS")).upper()

            if status != "FAIL":
                continue


            # ------------------------------------------------
            # 2. CHECK_ID 확인
            # ------------------------------------------------

            check_id = clean(row.get("CHECK_ID"))

            if not check_id:
                continue


            # ------------------------------------------------
            # 3. 기존 mapping.yml에 있으면 제외
            #
            # 이미 approve로 작업한 정책들은 건드리지 않는다.
            # ------------------------------------------------

            if check_id in existing_check_ids:
                continue


            # ------------------------------------------------
            # 4. 같은 CHECK_ID가 여러 finding에 존재할 수 있으므로
            #    한 번만 저장
            # ------------------------------------------------

            if check_id in candidates:
                continue


            # ------------------------------------------------
            # 5. 후보 데이터 생성
            #
            # mode는 아직 manual / not_supported 중 확정 전
            # ------------------------------------------------

            candidates[check_id] = {
                "mode": None,

                "severity": clean(
                    row.get("SEVERITY")
                ),

                "service": clean(
                    row.get("SERVICE_NAME")
                ),

                "resource_type": clean(
                    row.get("RESOURCE_TYPE")
                ),

                "remediation": {
                    "description": clean(
                        row.get(
                            "REMEDIATION_RECOMMENDATION_TEXT"
                        )
                    ),

                    "cli": clean(
                        row.get(
                            "REMEDIATION_CODE_CLI"
                        )
                    ) or None,

                    "console": clean(
                        row.get(
                            "REMEDIATION_CODE_OTHER"
                        )
                    ) or None,

                    "docs_url": clean(
                        row.get(
                            "REMEDIATION_RECOMMENDATION_URL"
                        )
                    ) or None,
                },
            }

    return candidates


# ============================================================
# YAML 저장
# ============================================================

def save_candidates(candidates, output_path):

    with output_path.open(
        "w",
        encoding="utf-8"
    ) as f:

        yaml.safe_dump(
            candidates,
            f,
            allow_unicode=True,
            sort_keys=False,
            default_flow_style=False,
        )


# ============================================================
# main
# ============================================================

def main():

    # 파일 확인
    if not INPUT_CSV.exists():
        raise FileNotFoundError(
            f"CSV 파일을 찾을 수 없습니다: {INPUT_CSV}"
        )

    if not MAPPING_YML.exists():
        raise FileNotFoundError(
            f"mapping.yml을 찾을 수 없습니다: {MAPPING_YML}"
        )


    # 기존 mapping check_id 읽기
    existing_check_ids = load_existing_mapping(
        MAPPING_YML
    )


    # CSV에서 아직 mapping되지 않은 FAIL 추출
    candidates = extract_candidates(
        INPUT_CSV,
        existing_check_ids
    )


    # YAML 저장
    save_candidates(
        candidates,
        OUTPUT_YML
    )


    print(
        f"기존 mapping check 수: "
        f"{len(existing_check_ids)}"
    )

    print(
        f"남은 후보 check 수: "
        f"{len(candidates)}"
    )

    print(
        f"출력 파일: {OUTPUT_YML}"
    )


if __name__ == "__main__":
    main()