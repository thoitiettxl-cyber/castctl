/** Pure line diff for the Config Editor diff modal.
 * Replaces @codemirror/merge: no editor dependency, trivially testable.
 * Output lines: ' ' context, '-' removed, '+' added. Common-prefix/suffix
 * trimming keeps small edits readable; middle blocks are shown whole.
 */

export type DiffLine = { kind: ' ' | '-' | '+'; text: string };

export function lineDiff(before: string, after: string): DiffLine[] {
  const a = before.split('\n');
  const b = after.split('\n');
  let start = 0;
  while (start < a.length && start < b.length && a[start] === b[start]) start++;
  let endA = a.length;
  let endB = b.length;
  while (endA > start && endB > start && a[endA - 1] === b[endB - 1]) {
    endA--;
    endB--;
  }
  const out: DiffLine[] = [];
  for (let i = 0; i < start; i++) out.push({ kind: ' ', text: a[i] });
  for (let i = start; i < endA; i++) out.push({ kind: '-', text: a[i] });
  for (let i = start; i < endB; i++) out.push({ kind: '+', text: b[i] });
  for (let i = endA; i < a.length; i++) out.push({ kind: ' ', text: a[i] });
  return out;
}

export function diffStats(lines: DiffLine[]): { additions: number; deletions: number } {
  return {
    additions: lines.filter((l) => l.kind === '+').length,
    deletions: lines.filter((l) => l.kind === '-').length,
  };
}
