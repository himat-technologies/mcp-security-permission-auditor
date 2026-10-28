import { parseConfig } from './parser';
import { scanValue } from './rules';
import { calculateScore } from './scoring';
import type { ScanResult } from '../types/security';
export function analyzeConfig(source: string): ScanResult {
 const parsed = parseConfig(source);
 if (!parsed.ok) return { valid:false, parseError:parsed.error, findings:[], score:0, risk:'Invalid Configuration', counts:{Critical:0,High:0,Medium:0,Low:0}, summary:'The input is not valid JSON. Correct the syntax before running the security analysis.' };
 const findings = scanValue(parsed.value); const score = calculateScore(findings);
 return {valid:true, parsed:parsed.value, findings, ...score, summary: findings.length ? `Found ${findings.length} potential issue(s). Review critical and high severity findings first.` : 'No issues were detected by the current rule set. This does not guarantee the configuration is secure.'};
}
