import { describe, expect, it } from 'vitest';
import { analyzeConfig } from '../src/engine/scanner';
import { redactSecrets } from '../src/engine/redaction';
import { calculateScore } from '../src/engine/scoring';
import { proposeRemediations, applySecretPlaceholder } from '../src/engine/remediation';
import { presets } from '../src/presets/examples';

describe('configuration scanner',()=>{
 it('reports invalid JSON with a useful error',()=>{const r=analyzeConfig('{ broken');expect(r.valid).toBe(false);expect(r.parseError).toBeTruthy();});
 it('flags root filesystem access',()=>{const r=analyzeConfig(presets.find(p=>p.id==='root')!.config);expect(r.findings.some(f=>f.ruleId==='SEC-FS-001')).toBe(true);});
 it('flags wildcard tool permissions',()=>{const r=analyzeConfig(presets.find(p=>p.id==='wildcard')!.config);expect(r.findings.some(f=>f.ruleId==='SEC-PERM-001')).toBe(true);});
 it('flags destructive commands',()=>{const r=analyzeConfig(presets.find(p=>p.id==='shell')!.config);expect(r.findings.some(f=>f.ruleId==='SEC-CMD-001')).toBe(true);});
 it('detects hardcoded credentials',()=>{const r=analyzeConfig(presets.find(p=>p.id==='secrets')!.config);expect(r.findings.some(f=>f.ruleId==='SEC-SECRET-001')).toBe(true);});
 it('does not report environment placeholders as literal secrets',()=>{const r=analyzeConfig(JSON.stringify({mcpServers:{x:{env:{API_KEY:'${API_KEY}'}}}}));expect(r.findings.some(f=>f.ruleId==='SEC-SECRET-001')).toBe(false);});
 it('returns bounded score and severity counts',()=>{const r=analyzeConfig(presets.find(p=>p.id==='root')!.config);expect(r.score).toBeGreaterThanOrEqual(0);expect(r.score).toBeLessThanOrEqual(100);expect(r.counts.Critical).toBeGreaterThan(0);});
 it('deduplicates identical findings by id',()=>{const f:any={id:'same',ruleId:'X',title:'x',severity:'High',description:'',path:'$',evidence:'',remediation:'',confidence:'High'};expect(calculateScore([f,f]).score).toBe(78);});
 it('redacts common token patterns',()=>{expect(redactSecrets('token=ghp_abcdefghijklmnopqr')).toContain('[REDACTED_SECRET]');});
 it('provides manual-review remediations for wildcard values',()=>{const cfg={mcpServers:{x:{allowedTools:['*'],extra:true}}};const fixes=proposeRemediations(cfg);expect(fixes.some(f=>f.after.includes('ALLOWLIST'))).toBe(true);});
 it('preserves unrelated properties while replacing credential-like fields',()=>{const result=applySecretPlaceholder({other:42,env:{API_KEY:'secret-value'}}) as any;expect(result.other).toBe(42);expect(result.env.API_KEY).toBe('${API_KEY}');});
});
