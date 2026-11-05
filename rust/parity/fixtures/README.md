# Parity fixtures (invented values only)

- `config.json` (F1): the minimal single-file config used as the
  fixture config for golden generation. It has NO `log` block.
- `config-telegram.json` (F2): a config with a telegram block. The
  token is a SHAPE-ONLY FAKE (`123456789:ABCDEFGHIJKLMNOPQRST`) —
  never a real credential. F2 is not consumed by any golden case;
  it exists for future harness cases that do.
- `bad-config.json`: `{invalid`, consumed by case 55.
- `decoder-truncated-array.json`, `decoder-bad-exponent.json`,
  `decoder-bad-escape.json`, `decoder-bad-unicode.json`: the four
  decoder-message fixtures from the fix-loop round 2 binary
  probes (cases 56–59), one per fixed message shape. All are
  invented values; none ends with a trailing newline.
