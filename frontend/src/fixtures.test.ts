import { demoCoverage, demoIssueList, demoResults, demoScan } from './fixtures';

describe('explicit demo scan fixtures', () => {
  it('keeps the completed progress snapshot internally consistent', () => {
    expect(demoScan.status).toBe('COMPLETED');
    expect(demoScan.progressPercent).toBe(100);
    expect(demoScan.completedUnits).toBe(demoScan.totalUnits);
    expect(demoScan.engineSnapshot?.executedRuleCount).toBe(79);
  });

  it('contains exactly the ordered 49 KISA results with valid finding counts', () => {
    expect(demoResults.totalWeaknessCount).toBe(49);
    expect(demoResults.results).toHaveLength(49);
    expect(demoResults.results.map((result) => result.weaknessId)).toEqual(
      Array.from({ length: 49 }, (_, index) => `KISA-2021-${String(index + 1).padStart(2, '0')}`),
    );
    for (const result of demoResults.results) {
      expect(result.findingCount).toBe(result.findings.length);
    }
  });

  it('keeps only confirmed detections and explicit v2 coverage states', () => {
    for (const result of demoResults.results) {
      if (result.findingCount > 0) {
        expect(result.resultStatus).toBe('DETECTED');
        expect(result.findings.every((finding) => finding.kind === 'DETECTED')).toBe(true);
      } else {
        expect(['NOT_DETECTED', 'NOT_SUPPORTED']).toContain(result.resultStatus);
      }
      expect(result.languages).toHaveLength(3);
      expect(result.languages?.every((language) => ['DETECTED', 'NOT_DETECTED', 'NOT_SUPPORTED', 'CHECK_FAILED'].includes(language.resultStatus))).toBe(true);
    }
    for (const number of [46, 47, 49]) {
      const result = demoResults.results[number - 1];
      expect(result.languages?.find((language) => language.language === 'Java')?.supportStatus).toBe('SUPPORTED');
      expect(result.languages?.filter((language) => language.language !== 'Java').every((language) => language.supportStatus === 'NOT_SUPPORTED')).toBe(true);
    }
  });

  it('provides all 49 coverage criteria while retaining legacy issue availability', () => {
    expect(demoCoverage.totalWeaknessCount).toBe(49);
    expect(demoCoverage.summary.totalCriterionCount).toBe(49);
    expect(demoCoverage.items).toHaveLength(49);
    expect(demoCoverage.coverageModelVersion).toBe(2);
    expect(demoCoverage.summary.issueStats).toBeNull();
    expect(demoIssueList()).toMatchObject({
      issueModelAvailable: false,
      unavailableReason: 'LEGACY_SCAN',
      items: [],
      total: 0,
      nextCursor: null,
      stats: null,
    });
  });
});
