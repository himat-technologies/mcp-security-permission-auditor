export function parseConfig(source: string): { ok: true; value: unknown } | { ok: false; error: string } {
  try { return { ok: true, value: JSON.parse(source) as unknown }; }
  catch (error) {
    const message = error instanceof Error ? error.message : 'Invalid JSON';
    const match = message.match(/position\s+(\d+)/i);
    if (match) { const position = Number(match[1]); const before = source.slice(0, position); const line = before.split('\n').length; const column = position - before.lastIndexOf('\n'); return { ok: false, error: `${message} (line ${line}, column ${column})` }; }
    return { ok: false, error: message };
  }
}
