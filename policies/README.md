# Cloud Custodian 정책

Prowler 가 탐지한 FAIL 항목을 Cloud Custodian 으로 조치하기 위한 정책 파일 모음이다.
Policies 폴더 아래의 정책들이 AWS 를 직접 조회해 대상 리소스를 찾고 **조치**를 수행한다.

Prowler 와 Custodian 은 서로 직접 연결되지 않는다.
두 도구의 연결은 상위 폴더의 `mapping.yml` 이 맡고, 여기 있는 정책 파일들은 실제 조치 방법만 담는다.

정책 파일은 서비스 단위로 나뉜다 (`s3.yml`, `ec2.yml`, …).
각 파일은 최상위 `policies:` 아래에 여러 정책을 나열한다.

---

## 정책 이름

각 정책의 `name` 은 Prowler `check_id` 의 `_` 를 `-` 로 바꾼 값을 쓴다.

```
ec2_instance_imdsv2_enabled   →   ec2-instance-imdsv2-enabled
```

이 규칙 덕분에 `mapping.yml` 에서 정책 이름을 따로 적지 않아도 코드가 알아서 찾는다.

---

## 정책 구조

정책 하나는 이렇게 생겼다.

```yaml
- name: s3-bucket-kms-encryption
  resource: aws.s3
  description: SSE-KMS 기본 암호화가 설정되지 않은 S3 Bucket
  metadata:
    prowler_check: s3_bucket_kms_encryption
    remediation_summary: 기본 암호화를 SSE-KMS 로 활성화한다
    note: |
      기존 접근 주체에 KMS 권한이 필요할 수 있어 approve 로 분류한다
  filters:
    - not:
      - type: bucket-encryption
        state: true
        crypto: aws:kms
  actions:
    - type: set-bucket-encryption
      crypto: aws:kms
```

### 필드 역할

| 필드 | 역할 |
| --- | --- |
| `name` | 정책의 고유 이름. `mapping.yml` 의 `policy` 값과 일치해야 한다 |
| `resource` | Custodian 이 조회할 AWS 리소스 종류 (`aws.s3`, `aws.ec2`, `aws.account` …) |
| `description` | 어떤 취약 상태를 대상으로 하는 정책인지 한 줄 설명 |
| `metadata` | Prowler 연동과 정책 관리를 위한 메모. Custodian 이 공식 지원하는 필드라 파일만 봐도 맥락을 알 수 있게 남긴다 |
| `filters` | 조회한 리소스 중 실제 조치가 필요한 것만 골라내는 조건 |
| `actions` | 골라낸 리소스에 수행할 AWS 설정 변경 |

### `metadata` 하위 필드

| 하위 필드 | 내용 |
| --- | --- |
| `prowler_check` | 이 정책이 대응하는 Prowler `check_id` |
| `remediation_summary` | 정책이 수행하는 조치를 한 줄로 요약 |
| `note` | 자동 조치 시 주의사항, `approve` 로 분류한 근거 등 |

---

## `filters` 와 `actions`

기본 흐름.

```
resource  →  AWS 리소스 조회  →  filters  →  조치 대상 선별  →  actions  →  설정 변경
```

- **`filters`** 는 Prowler 가 FAIL 로 판단한 상태와 최대한 같은 조건으로 쓴다.
  범위가 넓으면 Prowler 가 탐지하지 않은 정상 리소스까지 조치 대상에 들어간다.
- **`actions`** 는 FAIL 원인이 되는 설정을 정상 상태로 되돌리는 것만 쓴다.
  태그 추가처럼 취약 설정 자체를 고치지 않는 것은 remediation 으로 보지 않는다.

리소스 종류마다 쓸 수 있는 filter / action 이 다르므로 문법은 아래로 확인한다.

```bash
custodian schema aws.s3.actions.set-bucket-encryption
custodian schema aws.s3.filters.bucket-encryption
```

---

## 실행

작성 후 스키마 검증부터 한다.

```bash
custodian validate policies/s3.yml
```

이 프로젝트에서 정책은 항상 `--dryrun` 으로 돈다. **`actions` 가 있어도 실제
AWS 변경은 일어나지 않는다** — "이대로 실행하면 뭐가 바뀔지" 만 출력된다.
실조치를 켜기 전에 Prowler finding 의 리소스와 Custodian 이 선별한 리소스가
일치하는지 반드시 대조한다.