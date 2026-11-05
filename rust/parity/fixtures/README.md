# Parity fixtures (invented values only)

- `config.json` (F1): the minimal single-file config used as the
  fixture config for golden generation. It has NO `log` block.
- `config-telegram.json` (F2): a config with a telegram block. The
  token is a SHAPE-ONLY FAKE (`123456789:ABCDEFGHIJKLMNOPQRST`) —
  never a real credential. F2 is not consumed by the 54 golden
  cases (none of them reads a config file); it exists for future
  harness cases that do.
