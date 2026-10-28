import type { Finding, Severity } from '../types/security';
export const WEIGHTS: Record<Severity, number> = { Critical: 35, High: 22, Medium: 12, Low: 5 };
export function calculateScore(findings: Finding[]): { score: number; risk: string; counts: Record<Severity, number> } {
  const unique = [...new Map(findings.map(f => [f.id, f])).values()];
  const score = Math.max(0, Math.min(100, 100 - unique.reduce((sum, f) => sum + WEIGHTS[f.severity], 0)));
  const risk = score >= 90 ? 'Low Risk' : score >= 70 ? 'Moderate Risk' : score >= 40 ? 'High Risk' : 'Critical Risk';
  const counts: Record<Severity, number> = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  unique.forEach(f => counts[f.severity]++);
  return { score, risk, counts };
}
