export function bytes(n: number | null | undefined): string {
  if (!n) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return i === 0 ? `${n} B` : `${v.toFixed(v < 10 ? 1 : 0)} ${units[i]}`;
}

export function when(epochSeconds: number): string {
  const d = new Date(epochSeconds * 1000);
  return d.toLocaleString(undefined, {
    year: "numeric", month: "short", day: "2-digit",
    hour: "2-digit", minute: "2-digit",
  });
}

/// Seconds as something a person says out loud.
export function duration(secs: number): string {
  if (secs < 60) return `${secs}s`;
  if (secs < 3600) return `${Math.round(secs / 60)} min`;
  const h = secs / 3600;
  return h < 24 ? `${h % 1 === 0 ? h : h.toFixed(1)} h` : `${Math.round(h / 24)} d`;
}

/// The last two path components, which is what identifies a file to a human.
export function shortPath(p: string): string {
  const parts = p.split("/").filter(Boolean);
  return parts.length <= 2 ? p : "…/" + parts.slice(-2).join("/");
}

export function homeRelative(p: string): string {
  return p.replace(/^\/Users\/[^/]+/, "~");
}

/// Subsequence match with a score, the way a settings search should behave.
///
/// Not a substring match: typing "trsh" should still find "Never emptied from
/// the Trash", and "devcache" should find "Developer tools". Characters must
/// appear in order but need not be adjacent, and runs that *are* adjacent —
/// or that start a word — score higher, so the closest match sorts first.
///
/// Returns null when the query does not match at all, so callers can filter
/// and rank in one pass.
export function fuzzyScore(query: string, text: string): number | null {
  const q = query.trim().toLowerCase();
  if (!q) return 0;
  const t = text.toLowerCase();

  let score = 0;
  let ti = 0;
  let streak = 0;
  for (const ch of q) {
    const found = t.indexOf(ch, ti);
    if (found === -1) return null;
    // A character that continues a run, or starts a word, is a better match
    // than one that merely appears somewhere later.
    const atWordStart = found === 0 || /[\s./_-]/.test(t[found - 1]);
    streak = found === ti ? streak + 1 : 0;
    score += 1 + streak * 2 + (atWordStart ? 3 : 0);
    ti = found + 1;
  }
  // Prefer shorter haystacks: an exact-length match beats a stray hit inside a
  // long paragraph.
  return score - t.length / 200;
}
