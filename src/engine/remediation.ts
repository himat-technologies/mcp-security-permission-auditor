export interface ProposedChange { id: string; title: string; reason: string; before: string; after: string; apply: (input: Record<string, unknown>) => Record<string, unknown>; }
export function proposeRemediations(input: unknown): ProposedChange[] {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return [];
  const config = input as Record<string, unknown>; const changes: ProposedChange[] = [];
  const serversKey = config.mcpServers ? 'mcpServers' : config.servers ? 'servers' : '';
  const servers = serversKey ? config[serversKey] as Record<string, unknown> : undefined;
  if (servers && typeof servers === 'object' && !Array.isArray(servers)) {
    for (const [name, raw] of Object.entries(servers)) {
      if (!raw || typeof raw !== 'object' || Array.isArray(raw)) continue;
      const server = raw as Record<string, unknown>;
      for (const key of ['args','allowedTools','allowed_tools','permissions','autoApprove','auto_approve']) {
        const val = server[key];
        if (typeof val === 'string' && /(^|[\\/])\.\.?([\\/]|$)|^(\/|[A-Za-z]:[\\/]?$)/.test(val)) {
          changes.push({ id:`path-${name}-${key}`, title:`Review broad path in ${name}`, reason:'The path may be broader than intended. A safe replacement depends on your workspace, so this change is for manual review only.', before:val, after:'[MANUAL REVIEW REQUIRED]', apply:(x)=>x });
        }
        if (Array.isArray(val) && val.includes('*')) {
          changes.push({ id:`wildcard-${name}-${key}`, title:`Replace wildcard in ${name}`, reason:'Wildcard permissions are too context-dependent to replace safely. Choose the exact tools or commands this server requires.', before:JSON.stringify(val), after:'[DEFINE EXPLICIT ALLOWLIST]', apply:(x)=>x });
        }
      }
    }
  }
  return changes;
}
export function applySecretPlaceholder(input: unknown): unknown {
  if (Array.isArray(input)) return input.map(applySecretPlaceholder);
  if (!input || typeof input !== 'object') return input;
  const out: Record<string, unknown> = {};
  for (const [key,val] of Object.entries(input as Record<string, unknown>)) {
    if (/(api[_-]?key|access[_-]?token|password|passwd|client[_-]?secret|authorization|private[_-]?key)/i.test(key) && typeof val === 'string' && val.length > 3 && !/^\$\{[^}]+\}$/.test(val)) out[key] = '${' + key.toUpperCase().replace(/[^A-Z0-9]/g,'_') + '}';
    else out[key] = applySecretPlaceholder(val);
  }
  return out;
}
