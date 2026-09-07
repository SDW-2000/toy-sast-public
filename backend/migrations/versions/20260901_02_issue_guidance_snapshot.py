"""Add immutable source-free guidance snapshots to normalized issues."""

from collections.abc import Sequence

from alembic import op

revision: str = "20260901_02"
down_revision: str | None = "20260901_01"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # The prior revision freezes completed children. DDL locks and the migration
    # transaction protect this bounded backfill while that trigger is absent.
    op.execute("DROP TRIGGER scan_issues_completed_immutable ON scan_issues")
    op.execute(
        """
        ALTER TABLE scan_issues
        ADD COLUMN guidance_version smallint,
        ADD COLUMN automation_limitation text,
        ADD COLUMN manual_verification_checks jsonb,
        ADD COLUMN remediation text,
        ADD COLUMN safe_implementation_example text,
        ADD COLUMN guidance_references jsonb
        """
    )
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1 FROM scan_issues
                WHERE cwe_id IS NOT NULL AND cwe_id !~ '^CWE-[1-9][0-9]{0,5}$'
            ) THEN
                RAISE EXCEPTION 'stored issue CWE IDs must be canonical before guidance backfill';
            END IF;
        END $$
        """
    )
    op.execute(
        """
        UPDATE scan_issues
        SET guidance_version = 1,
            automation_limitation = CASE finding_kind
                WHEN 'DETECTED' THEN concat(
                    '정적 규칙은 표시된 위치의 위험 패턴만 식별합니다. ',
                    '실제 입력 도달성, 실행 경로, 주변 방어 로직의 유효성은 ',
                    '자동으로 확인하지 않습니다.'
                )
                ELSE concat(
                    '이 검토 신호는 위험 관련 코드의 존재만 식별하며 ',
                    '취약 여부를 자동 판정하지 않습니다. 업무 정책, 권한, ',
                    '실행 상태를 사람이 확인해야 합니다.'
                )
            END,
            manual_verification_checks = CASE finding_kind
                WHEN 'DETECTED' THEN jsonb_build_array(
                    '표시된 연산까지 외부 입력이 도달하는지 데이터 흐름을 확인합니다.',
                    concat(
                        '허용 목록, 인코딩, 권한 검사 등 방어 로직이 ',
                        '모든 실행 경로에 적용되는지 확인합니다.'
                    ),
                    '안전한 입력과 공격 입력으로 수정 전후 동작을 재현합니다.'
                )
                ELSE jsonb_build_array(
                    '표시된 코드가 실제 보안 경계나 민감 기능에 관여하는지 확인합니다.',
                    concat(
                        '업무 정책, 인증·인가, 자원 수명주기 조건이 ',
                        '모든 실행 경로에서 지켜지는지 확인합니다.'
                    ),
                    concat(
                        '정상 사용과 오용 시나리오를 수동으로 실행하여 ',
                        '보호 조치의 동작을 확인합니다.'
                    )
                )
            END,
            remediation = left(
                '현재 규칙 신호: ' || message ||
                concat(
                    ' 신뢰되지 않은 값을 보안 민감 연산에 직접 전달하지 말고, ',
                    '업무에 맞는 허용 목록 검증과 안전한 전용 API를 ',
                    '경계에서 적용합니다.'
                ),
                4000
            ),
            safe_implementation_example = CASE language
                WHEN 'Java' THEN concat(
                    '개념 예시(원본 코드 아님): String validated = ',
                    'validator.requireAllowed(untrustedInput); ',
                    'trustedApi.execute(validated); 실제 허용 규칙과 ',
                    '전용 API는 업무 맥락에 맞게 정의합니다.'
                )
                WHEN 'JavaScript' THEN concat(
                    '개념 예시(원본 코드 아님): const validated = ',
                    'requireAllowed(untrustedInput); ',
                    'await trustedApi.execute(validated); 실제 허용 규칙과 ',
                    '전용 API는 업무 맥락에 맞게 정의합니다.'
                )
                ELSE concat(
                    '개념 예시(원본 코드 아님): validated = ',
                    'require_allowed(untrusted_input); ',
                    'trusted_api.execute(validated) 실제 허용 규칙과 ',
                    '전용 API는 업무 맥락에 맞게 정의합니다.'
                )
            END,
            guidance_references = CASE
                WHEN cwe_id IS NOT NULL THEN jsonb_build_array(
                    'https://cwe.mitre.org/data/definitions/' ||
                    substring(cwe_id FROM 5) || '.html'
                )
                ELSE jsonb_build_array('https://cwe.mitre.org/data/index.html')
            END
        """
    )
    op.execute(
        """
        ALTER TABLE scan_issues
        ALTER COLUMN guidance_version SET NOT NULL,
        ALTER COLUMN automation_limitation SET NOT NULL,
        ALTER COLUMN manual_verification_checks SET NOT NULL,
        ALTER COLUMN remediation SET NOT NULL,
        ALTER COLUMN safe_implementation_example SET NOT NULL,
        ALTER COLUMN guidance_references SET NOT NULL
        """
    )
    op.execute(
        """
        ALTER TABLE scan_issues ADD CONSTRAINT scan_issues_guidance_snapshot_check CHECK (
            guidance_version = 1
            AND char_length(automation_limitation) BETWEEN 1 AND 4000
            AND jsonb_typeof(manual_verification_checks) = 'array'
            AND jsonb_array_length(manual_verification_checks) BETWEEN 1 AND 5
            AND char_length(remediation) BETWEEN 1 AND 4000
            AND char_length(safe_implementation_example) BETWEEN 1 AND 4000
            AND jsonb_typeof(guidance_references) = 'array'
            AND jsonb_array_length(guidance_references) BETWEEN 1 AND 3
        )
        """
    )
    op.execute(
        """
        CREATE TRIGGER scan_issues_completed_immutable
        BEFORE INSERT OR UPDATE OR DELETE ON scan_issues
        FOR EACH ROW EXECUTE FUNCTION reject_completed_scan_child_mutation()
        """
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER scan_issues_completed_immutable ON scan_issues")
    op.execute("ALTER TABLE scan_issues DROP CONSTRAINT scan_issues_guidance_snapshot_check")
    op.execute(
        """
        ALTER TABLE scan_issues
        DROP COLUMN guidance_references,
        DROP COLUMN safe_implementation_example,
        DROP COLUMN remediation,
        DROP COLUMN manual_verification_checks,
        DROP COLUMN automation_limitation,
        DROP COLUMN guidance_version
        """
    )
    op.execute(
        """
        CREATE TRIGGER scan_issues_completed_immutable
        BEFORE INSERT OR UPDATE OR DELETE ON scan_issues
        FOR EACH ROW EXECUTE FUNCTION reject_completed_scan_child_mutation()
        """
    )
