"""Add immutable source-free detection basis snapshots to normalized issues."""

from collections.abc import Sequence

from alembic import op

revision: str = "20260901_03"
down_revision: str | None = "20260901_02"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # PostgreSQL runs the revision in one transaction. The table lock protects the
    # bounded backfill while the completed-child mutation trigger is absent.
    op.execute("DROP TRIGGER scan_issues_completed_immutable ON scan_issues")
    op.execute(
        """
        ALTER TABLE scan_issues
        ADD COLUMN detection_basis_version smallint,
        ADD COLUMN confidence text,
        ADD COLUMN detection_rationale text
        """
    )
    op.execute(
        """
        WITH normalized_fragments AS (
            SELECT issue_id,
                   concat(
                       regexp_replace(
                           rtrim(
                               coalesce(nullif(rule_description, ''), '정보 없음'), ' '
                           ),
                           '[.!?。！？]+$', ''
                       ),
                       CASE
                           WHEN right(
                               rtrim(
                                   coalesce(nullif(rule_description, ''), '정보 없음'),
                                   ' '
                               ), 1
                           ) IN ('.', '!', '?', '。', '！', '？')
                           THEN right(
                               rtrim(
                                   coalesce(nullif(rule_description, ''), '정보 없음'),
                                   ' '
                               ), 1
                           )
                           ELSE '.'
                       END
                   ) AS rule_description_sentence,
                   concat(
                       regexp_replace(rtrim(message, ' '), '[.!?。！？]+$', ''),
                       CASE
                           WHEN right(rtrim(message, ' '), 1)
                               IN ('.', '!', '?', '。', '！', '？')
                           THEN right(rtrim(message, ' '), 1)
                           ELSE '.'
                       END
                   ) AS message_sentence
            FROM scan_issues
        )
        UPDATE scan_issues AS issue
        SET detection_basis_version = 1,
            confidence = CASE finding_kind
                WHEN 'DETECTED' THEN 'MEDIUM'
                ELSE 'LOW'
            END,
            detection_rationale = left(
                CASE finding_kind
                    WHEN 'DETECTED' THEN concat(
                        '규칙 ', rule_id,
                        '이 저장된 규칙 설명과 탐지 메시지에 해당하는 위험 패턴을 ',
                        '탐지했습니다. 이 결과는 자동 패턴 일치 근거이며 실제 실행 ',
                        '가능성은 별도 검증해야 합니다. 규칙 설명: ',
                        normalized.rule_description_sentence,
                        ' 탐지 메시지: ', normalized.message_sentence
                    )
                    ELSE concat(
                        '규칙 ', rule_id,
                        '이 저장된 규칙 설명과 탐지 메시지에 해당하는 수동 검토 ',
                        '신호를 식별했습니다. 이 신호만으로 취약 여부를 확정할 수 ',
                        '없으며 수동 검증이 필요합니다. 규칙 설명: ',
                        normalized.rule_description_sentence,
                        ' 탐지 메시지: ', normalized.message_sentence
                    )
                END,
                4000
            )
        FROM normalized_fragments AS normalized
        WHERE normalized.issue_id = issue.issue_id
        """
    )
    op.execute(
        """
        ALTER TABLE scan_issues
        ALTER COLUMN detection_basis_version SET NOT NULL,
        ALTER COLUMN confidence SET NOT NULL,
        ALTER COLUMN detection_rationale SET NOT NULL
        """
    )
    op.execute(
        """
        ALTER TABLE scan_issues ADD CONSTRAINT scan_issues_detection_snapshot_check CHECK (
            detection_basis_version = 1
            AND confidence IN ('MEDIUM', 'LOW')
            AND (
                (finding_kind = 'DETECTED' AND confidence = 'MEDIUM')
                OR (finding_kind = 'REVIEW_SIGNAL' AND confidence = 'LOW')
            )
            AND char_length(detection_rationale) BETWEEN 1 AND 4000
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
    op.execute("ALTER TABLE scan_issues DROP CONSTRAINT scan_issues_detection_snapshot_check")
    op.execute(
        """
        ALTER TABLE scan_issues
        DROP COLUMN detection_rationale,
        DROP COLUMN confidence,
        DROP COLUMN detection_basis_version
        """
    )
    op.execute(
        """
        CREATE TRIGGER scan_issues_completed_immutable
        BEFORE INSERT OR UPDATE OR DELETE ON scan_issues
        FOR EACH ROW EXECUTE FUNCTION reject_completed_scan_child_mutation()
        """
    )
