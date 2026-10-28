import type { Finding, Severity } from '../types/security';
import { redactSecrets } from './redaction';
const weights: Record<Severity, number> = { Critical: 35, High: 22, Medium: 12, Low: 5 };
function finding(ruleId: string, title: string, severity: Severity, description: string, path: string, evidence: string, remediation: string, confidence: Finding['confidence']='High'): Finding {
  return { id: ruleId + ':' + path, ruleId, title, severity, description, path, evidence: redactSecrets(evidence.slice(0, 180)), remediation, confidence };
}
function walk(value: unknown, path = '$', out: Finding[] = []): Finding[] {
  if (typeof value === 'string') {
    if (/\b(sk-[A-Za-z0-9_-]{8,}|gh[pousr]_[A-Za-z0-9]{10,}|AKIA[0-9A-Z]{16})\b/.test(value)) out.push(finding('SEC-SECRET-002','Token-like value detected','Critical','A string matches a common token pattern.',path,value,'Revoke or rotate the token, remove it from configuration, and use a secret manager.'));
    if (/(^|[\\/])(?:\.\.[\\/])/.test(value)) out.push(finding('SEC-FS-003','Parent-directory traversal pattern','High','The path includes parent-directory traversal, which may escape an intended workspace.',path,value,'Resolve paths against an explicit workspace root and reject paths that resolve outside it.'));
    if (/\brm\s+-rf\b|\bchmod\s+-R\s+777\b|\bmkfs\b|\bdd\s+if=/.test(value)) out.push(finding('SEC-CMD-001','Potentially destructive command','Critical','A command string contains a destructive or overly permissive shell pattern.',path,value,'Remove destructive commands from automatic approvals and require explicit human review.'));
    if (/(curl|wget).{0,100}(\|\s*(sh|bash)|python\s+-c)/i.test(value)) out.push(finding('SEC-CMD-002','Remote content may be executed','High','A command appears to download content and pass it to an interpreter.',path,value,'Avoid piping remote downloads into a shell; pin and verify artifacts before execution.'));
    if (/^(\/|[A-Za-z]:[\\/]?$)/.test(value.trim())) out.push(finding('SEC-FS-001','Root-level filesystem access','Critical','A configured path appears to grant access from a filesystem root.',path,value,'Restrict access to a dedicated project/workspace directory and verify the server enforces the boundary.'));
    return out;
  }
  if (Array.isArray(value)) { value.forEach((v,i)=>walk(v, `${path}[${i}]`, out)); return out; }
  if (!value || typeof value !== 'object') return out;
  for (const [key, val] of Object.entries(value as Record<string, unknown>)) {
    const p = `${path}.${key}`; const text = typeof val === 'string' ? val : '';
    if (typeof val === 'string' && /(api[_-]?key|access[_-]?token|password|passwd|client[_-]?secret|authorization|private[_-]?key)/i.test(key) && text.length > 3 && !/^\$\{[^}]+\}$/.test(text) && !/^(your_|<|\[redacted)/i.test(text)) {
      out.push(finding('SEC-SECRET-001','Possible hardcoded secret','Critical','A credential-like field contains a literal value. Verify whether it is a real secret.',p,`${key}: ${text}`, 'Move the value to a secure environment variable or secret manager and rotate any exposed credential.'));
    }
    if (typeof val === 'string' && /\b(sk-[A-Za-z0-9_-]{8,}|gh[pousr]_[A-Za-z0-9]{10,}|AKIA[0-9A-Z]{16})\b/.test(text)) out.push(finding('SEC-SECRET-002','Token-like value detected','Critical','A string matches a common token pattern.',p,text,'Revoke or rotate the token, remove it from configuration, and use a secret manager.'));
    if (typeof val === 'string' && /(^|[\\/])(?:\.{2}[\\/])/.test(text)) out.push(finding('SEC-FS-003','Parent-directory traversal pattern','High','The path includes parent-directory traversal, which may escape an intended workspace.',p,text,'Resolve paths against an explicit workspace root and reject paths that resolve outside it.'));
    if (typeof val === 'string' && /^(\/|[A-Za-z]:[\\/]?$)/.test(text.trim())) out.push(finding('SEC-FS-001','Root-level filesystem access','Critical','A configured path appears to grant access from a filesystem root.',p,text,'Restrict access to a dedicated project/workspace directory and verify the server enforces the boundary.'));
    if (typeof val === 'string' && /\brm\s+-rf\b|\bchmod\s+-R\s+777\b|\bmkfs\b|\bdd\s+if=/.test(text)) out.push(finding('SEC-CMD-001','Potentially destructive command','Critical','A command string contains a destructive or overly permissive shell pattern.',p,text,'Remove destructive commands from automatic approvals and require explicit human review.'));
    if (typeof val === 'string' && /(curl|wget).{0,100}(\|\s*(sh|bash)|python\s+-c)/i.test(text)) out.push(finding('SEC-CMD-002','Remote content may be executed','High','A command appears to download content and pass it to an interpreter.',p,text,'Avoid piping remote downloads into a shell; pin and verify artifacts before execution.'));
    if (typeof val === 'string' && /^(\*|\*\.\*)$/.test(text.trim()) && /(tool|permission|allow|approval|command)/i.test(key)) out.push(finding('SEC-PERM-001','Wildcard permission or approval','High','A wildcard may grant broad access to tools or commands.',p,text,'Replace wildcard access with a short, explicit allowlist of required tools or commands.'));
    if (Array.isArray(val) && val.some(v=>v==='*') && /(tool|permission|allow|approval|command)/i.test(key)) out.push(finding('SEC-PERM-001','Wildcard permission or approval','High','A permission list includes a wildcard entry.',p,JSON.stringify(val),'Replace wildcard access with a short, explicit allowlist.'));
    if (/^(tools|allowedTools|allowed_tools|permissions|autoApprove|auto_approve)$/i.test(key) && Array.isArray(val) && val.length > 12) out.push(finding('SEC-PERM-002','Broad permission list','Medium','The permission list is unusually large and may be difficult to audit.',p,`${val.length} entries`,'Review whether each permission is necessary and remove unused entries.','Medium'));
    if (typeof val === 'object' && val !== null && !Array.isArray(val) && /^(inputSchema|input_schema|parameters|schema)$/i.test(key)) {
      const schema = val as Record<string, unknown>;
      if (schema.type === 'object' && !Array.isArray(schema.required)) out.push(finding('SEC-SCHEMA-001','Schema has no required-field list','Low','Object inputs do not declare required fields; this may be intentional but reduces validation clarity.',p,JSON.stringify(schema).slice(0,150),'Declare required fields when the tool contract requires them.','Low'));
      if (schema.type === 'string' && typeof schema.maxLength !== 'number') out.push(finding('SEC-SCHEMA-002','String input has no maxLength','Low','Unbounded strings can increase validation and resource-use risks.',p,JSON.stringify(schema).slice(0,150),'Set a reasonable maxLength based on the tool contract.','Medium'));
      if (schema.type === 'array' && typeof schema.maxItems !== 'number') out.push(finding('SEC-SCHEMA-003','Array input has no maxItems','Low','Unbounded arrays may allow unexpectedly large input payloads.',p,JSON.stringify(schema).slice(0,150),'Set maxItems when the input domain has a reasonable upper bound.','Medium'));
    }
    walk(val, p, out);
  }
  return out;
}
export function scanValue(value: unknown): Finding[] {
  const findings = walk(value);
  const root = value as Record<string, unknown>;
  const servers = root && typeof root === 'object' ? (root.mcpServers ?? root.servers) : undefined;
  if (servers === undefined) findings.push(finding('SEC-CONFIG-001','MCP server definitions not found','Medium','Could not find a common mcpServers or servers property. This may be a valid client-specific format.', '$','Expected mcpServers or servers','Confirm the file format and server-definition key.','Low'));
  else if (!servers || typeof servers !== 'object' || Array.isArray(servers)) findings.push(finding('SEC-CONFIG-002','Malformed server definitions','High','Server definitions should normally be represented as an object keyed by server name.','$.'+(root.mcpServers?'mcpServers':'servers'),JSON.stringify(servers),'Correct the server definitions according to the client format.'));
  return [...new Map(findings.map(f=>[f.id,f])).values()];
}
export const severityPoints = weights;
