// A fail-closed lexical subset of workflow YAML. Mapping keys are decoded before
// inspection, in block and flow collections. Aliases, tags, explicit/complex
// keys, multiline quoted/plain action values and directives are unsupported.
// Literal/folded block bodies are skipped by indentation, never as YAML keys.
export function workflowUses(source) {
  if (source.length > 1024 * 1024 || /\r(?!\n)|\u0000/.test(source)) throw new Error('workflow YAML bound');
  const tokens = [];
  let blockIndent;
  for (const line of source.replaceAll('\r\n', '\n').split('\n')) {
    const indent = line.match(/^ */)[0].length;
    if (blockIndent !== undefined) {
      if (!line.trim() || indent > blockIndent) continue;
      blockIndent = undefined;
    }
    if (/^ *\t|^ *(?:[?:%]|---|\.\.\.)(?:\s|$)/.test(line)) throw new Error('unsupported workflow YAML');
    let i = indent;
    while (i < line.length) {
      if (/\s/.test(line[i])) { i++; continue; }
      if (line[i] === '#') break;
      if (line[i] === '-' && /\s/.test(line[i + 1] ?? '')) { i++; continue; }
      if ('{},[]:'.includes(line[i])) { tokens.push({ punctuation: line[i++] }); continue; }
      if ('&*!?|>%'.includes(line[i])) {
        if (/^[|>][1-9+-]{0,2}(?:\s+#.*)?\s*$/.test(line.slice(i))) {
          tokens.push({ block: true });
          blockIndent = line.match(/^ *(?:- +)*/)[0].length;
          break;
        }
        throw new Error('unsupported workflow YAML');
      }
      let value = '';
      if (line[i] === '"' || line[i] === "'") {
        const quote = line[i++];
        let closed = false;
        while (i < line.length) {
          const c = line[i++];
          if (c === quote) {
            if (quote === "'" && line[i] === "'") { value += "'"; i++; continue; }
            closed = true;
            break;
          }
          if (quote === '"' && c === '\\') {
            const escape = line[i++];
            const simple = { '0': '\0', a: '\x07', b: '\b', t: '\t', n: '\n', v: '\v', f: '\f', r: '\r', e: '\x1b', ' ': ' ', '"': '"', '/': '/', '\\': '\\', N: '\u0085', _: '\u00a0', L: '\u2028', P: '\u2029' };
            if (Object.hasOwn(simple, escape)) value += simple[escape];
            else if (['x', 'u', 'U'].includes(escape)) {
              const length = { x: 2, u: 4, U: 8 }[escape];
              const digits = line.slice(i, i + length);
              if (!new RegExp(`^[0-9a-fA-F]{${length}}$`).test(digits)) throw new Error('invalid YAML escape');
              value += String.fromCodePoint(Number.parseInt(digits, 16));
              i += length;
            } else throw new Error('unsupported YAML escape');
          } else value += c;
        }
        if (!closed) throw new Error('multiline workflow scalar unsupported');
      } else {
        const start = i;
        while (i < line.length) {
          if (line.startsWith('${{', i)) {
            const end = line.indexOf('}}', i + 3);
            if (end < 0) throw new Error('multiline workflow expression unsupported');
            i = end + 2;
            continue;
          }
          if ('{},[]'.includes(line[i]) || (line[i] === ':' && /[\s{},\[\]]/.test(line[i + 1] ?? ' ')) || (line[i] === '#' && /\s/.test(line[i - 1] ?? ' '))) break;
          i++;
        }
        value = line.slice(start, i).trim();
        if (!value) throw new Error('unsupported workflow YAML token');
      }
      tokens.push({ value });
    }
    tokens.push({ newline: true });
  }
  const uses = [];
  for (let i = 0; i < tokens.length; i++) {
    if (tokens[i].value !== 'uses' || tokens[i + 1]?.punctuation !== ':') continue;
    const action = tokens[i + 2];
    if (typeof action?.value !== 'string' || !action.value || /\s|\$\{\{/.test(action.value)) throw new Error('unsupported action reference');
    const after = tokens[i + 3];
    if (after && !after.newline && ![',', '}', ']'].includes(after.punctuation)) throw new Error('ambiguous action reference');
    uses.push(action.value);
  }
  return uses;
}
