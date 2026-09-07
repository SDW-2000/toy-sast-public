# Security Policy

## 지원 범위

이 저장소는 로컬 개발 및 폐쇄형 시연 환경을 위한 프로토타입입니다. 인터넷에 직접 노출하는 운영 배포는 지원하지 않습니다.

## 취약점 신고

실제 취약점 세부정보, 자격 증명, 소스코드 또는 재현 가능한 공격 데이터를 공개 Issue에 게시하지 마십시오.

다음 GitHub Private Vulnerability Reporting 경로를 이용해 비공개로 신고해 주세요.

https://github.com/SDW-2000/toy-sast-public/security/advisories/new

## 저장소 보안 원칙

- `.env`, 비밀번호 및 세션 비밀값을 커밋하지 않습니다.
- 실제 분석 대상 소스와 ZIP 파일을 커밋하지 않습니다.
- `analyzer/fixtures`에는 분석 규칙 검증을 위한 의도적으로 취약한 예제 코드가 포함됩니다.
- 분석 Worker는 비루트 사용자, 읽기 전용 파일시스템, capability 제거 및 제한된 자원으로 실행합니다.
- 비밀번호는 Argon2id로 해시합니다.
