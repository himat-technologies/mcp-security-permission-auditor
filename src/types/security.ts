export type Severity = 'Critical' | 'High' | 'Medium' | 'Low';
export interface Finding { id: string; ruleId: string; title: string; severity: Severity; description: string; path: string; evidence: string; remediation: string; confidence: 'High' | 'Medium' | 'Low'; }
export interface ScanResult { valid: boolean; parseError?: string; findings: Finding[]; score: number; risk: string; counts: Record<Severity, number>; summary: string; parsed?: unknown; }
export interface Preset { id: string; name: string; description: string; config: string; }
