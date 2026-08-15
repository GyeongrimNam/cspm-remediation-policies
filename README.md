# CSPM Remediation Policies

Prowler의 AWS 보안 점검 결과를 기반으로 Cloud Custodian 정책과 연결하여
취약 설정에 대한 대응 정책을 관리하기 위한 저장소입니다.

## 주요 구성

```text
.
├── mapping.yml
├── parsing.py
├── policies/
│   ├── cloudtrail.yml
│   ├── ec2.yml
│   ├── iam.yml
│   ├── s3.yml
│   └── vpc.yml
├── runbooks/
├── scripts/
│   └── migrate_policy_metadata.py
└── verification.yml
mapping.yml

Prowler check_id와 대응 정책을 연결합니다.

주요 정보:

Custodian policy
remediation mode
auto 실행 가능 여부
scope
risk note
guide
policies/

Cloud Custodian 정책을 서비스별로 관리합니다.

각 정책은 다음 구조를 사용합니다.

policies:
  - name: example-policy
    resource: aws.example


    metadata:
      prowler_check: example_check


      approve:
        disruption: none
        blast_radius: resource
        propagation_delay: immediate
        reversible: true
        cost_impact: none
        risk_note: ...


      auto:
        warning: ...
        allowed_scopes:
          - resource
        rollback_cli: null
        cooldown: 24h
        post_notification: log


    filters:
      - ...


    actions:
      - ...

auto는 mapping.yml에서 auto_eligible: true인 정책에만 존재합니다.

runbooks/

자동 조치가 불가능하거나 직접 조치가 필요한 경우 사용할
수동 대응 절차를 관리합니다.

verification.yml

Custodian 조치 이후 설정이 정상적으로 반영되었는지 확인하기 위한
검증 규칙을 관리합니다.

scripts/migrate_policy_metadata.py

mapping.yml을 기준으로 기존 Custodian 정책의 metadata를
현재 스키마로 마이그레이션하고 검증합니다.

python3 scripts/migrate_policy_metadata.py --check
python3 scripts/migrate_policy_metadata.py --apply
처리 흐름
Prowler Scan
    ↓
Finding Parsing
    ↓
mapping.yml
    ↓
Remediation Policy 선택
    ↓
Approve / Auto / Manual
    ↓
Cloud Custodian 실행
    ↓
Verification
    ↓
Prowler 재스캔
주의사항
Custodian 실행은 기본적으로 --dryrun을 통해 대상을 먼저 확인합니다.
실제 AWS 계정의 Prowler 원본 출력 및 자격증명은 Git에 저장하지 않습니다.
venv/, __pycache__/, Prowler 실행 결과 등은 .gitignore로 제외합니다.
