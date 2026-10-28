const SECRET_KEY = /(api[_-]?key|token|secret|password|passwd|private[_-]?key|client[_-]?secret|authorization)/i;
const SECRET_PATTERNS = [/(\bsk-[A-Za-z0-9_-]{8,}\b)/g, /(\bgh[pousr]_[A-Za-z0-9]{10,}\b)/g, /(\bAKIA[0-9A-Z]{16}\b)/g, /(-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----)/g];
export function redactSecrets(input: string): string {
  let out = input;
  for (const pattern of SECRET_PATTERNS) out = out.replace(pattern, '[REDACTED_SECRET]');
  out = out.replace(/("(?:api[_-]?key|access[_-]?token|token|secret|password|passwd|client[_-]?secret|authorization)"\s*:\s*")(.*?)"/gi, '$1[REDACTED_SECRET]"');
  return out;
}
export function isSecretKey(key: string): boolean { return SECRET_KEY.test(key); }
