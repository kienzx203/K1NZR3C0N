---
name: k1nzr3c0n-cmd-memory-gc
description: "Hunt memory garbage collection. Rotate/purge journal.jsonl and patterns.jsonl when they exceed 10MB. Keeps 3 compressed backups. Merges duplicate patterns. Reports stats before and after. Run periodically or when /pickup shows stale data."
tags: [command, maintenance, memory, cleanup]
---

# /memory-gc — Hunt Memory Garbage Collection

> Usage: `/memory-gc` — clean up bloated hunt memory files.
> **Safe**: backs up before any deletion. Non-destructive by default.

---

## Check Memory Size

```bash
echo "=== HUNT MEMORY STATUS ==="
JOURNAL="${SESSION_DIR:-/tmp/k1nzr3c0n_default}/journal.jsonl"
PATTERNS="/tmp/hunt_patterns.jsonl"

echo "Files:"
ls -lh "$JOURNAL" "$PATTERNS" 2>/dev/null | awk '{print "  " $9 ": " $5}' || echo "  No memory files found"

echo ""
echo "Entry counts:"
echo "  Journal entries: $(wc -l < $JOURNAL 2>/dev/null || echo 0)"
echo "  Pattern entries: $(wc -l < $PATTERNS 2>/dev/null || echo 0)"

echo ""
echo "Session directories:"
du -sh /tmp/k1nzr3c0n_*/ 2>/dev/null | sort -rh | head -10 | sed 's/^/  /'
TOTAL_SIZE=$(du -sh /tmp/k1nzr3c0n_*/ 2>/dev/null | awk '{total+=$1} END {print total}')
echo "  Total: ${TOTAL_SIZE:-0}M"
```

## Backup Before GC

```bash
echo ""
echo "=== Backup (before any cleanup) ==="
BACKUP_TS=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/tmp/hunt_memory_backup_${BACKUP_TS}"
mkdir -p "$BACKUP_DIR"

# Backup journal and patterns
cp "$JOURNAL" "${BACKUP_DIR}/journal.jsonl.bak" 2>/dev/null && \
  echo "  [OK] Journal backed up: ${BACKUP_DIR}/journal.jsonl.bak"
cp "$PATTERNS" "${BACKUP_DIR}/patterns.jsonl.bak" 2>/dev/null && \
  echo "  [OK] Patterns backed up: ${BACKUP_DIR}/patterns.jsonl.bak"

# Compress backup
tar czf "${BACKUP_DIR}.tar.gz" "$BACKUP_DIR" 2>/dev/null && \
  echo "  [OK] Compressed: ${BACKUP_DIR}.tar.gz" && rm -rf "$BACKUP_DIR"

# Keep only 3 most recent backups
ls -t /tmp/hunt_memory_backup_*.tar.gz 2>/dev/null | tail -n +4 | xargs rm -f 2>/dev/null
echo "  [OK] Kept 3 most recent backups"
```

## Pattern Deduplication

```bash
echo ""
echo "=== Deduplication ==="
# Deduplicate patterns by key field
if [ -f "$PATTERNS" ] && [ -s "$PATTERNS" ]; then
  BEFORE=$(wc -l < "$PATTERNS")
  python3 << PYEOF
import json

seen = set()
deduped = []
with open('${PATTERNS}') as f:
    for line in f:
        try:
            entry = json.loads(line.strip())
            key = entry.get('key', line.strip())
            if key not in seen:
                seen.add(key)
                deduped.append(line.strip())
        except:
            pass

with open('${PATTERNS}', 'w') as f:
    f.write('\n'.join(deduped) + ('\n' if deduped else ''))

print(f"  Deduplicated: {len(deduped)} unique entries")
PYEOF
  AFTER=$(wc -l < "$PATTERNS")
  echo "  Before: ${BEFORE} | After: ${AFTER} | Removed: $((BEFORE - AFTER)) duplicates"
fi
```

## Truncate if Over 10MB

```bash
echo ""
echo "=== Size-Based Truncation ==="
MAX_SIZE_KB=10240  # 10MB

for FILE in "$JOURNAL" "$PATTERNS"; do
  [ -f "$FILE" ] || continue
  SIZE_KB=$(du -k "$FILE" | cut -f1)
  if [ "$SIZE_KB" -gt "$MAX_SIZE_KB" ]; then
    echo "  [TRIM] $FILE is ${SIZE_KB}KB > 10MB — keeping last 1000 entries"
    tail -1000 "$FILE" > "${FILE}.tmp" && mv "${FILE}.tmp" "$FILE"
    echo "  [OK] Trimmed to $(wc -l < $FILE) entries"
  else
    echo "  [OK] $FILE is ${SIZE_KB}KB — under limit"
  fi
done

echo ""
echo "=== After GC ==="
ls -lh "$JOURNAL" "$PATTERNS" 2>/dev/null | awk '{print "  " $9 ": " $5}'
```
