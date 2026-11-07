"""argv this build deliberately does not implement.

The Rust artifact is the agent-facing CLI only (`rust/AGENT-CLI-SCOPE.md`):
`webui`, `telegram` and `plugin` are gone, and the top-level `--help`
therefore lists 43 commands where Go lists 46. Every Go-vs-Rust sweep
skips those argv and counts them as `skipped_dropped`, so DIFFS stays 0
for the surface both binaries still share.
"""

DROPPED_CMDS = {"webui", "telegram", "plugin"}
DROPPED_ARGV = {("--help",), ("-h",)}


def is_dropped(argv):
    """True when `argv` names (or asks help for) a dropped command."""
    if argv and argv[0] in DROPPED_CMDS:
        return True
    return tuple(argv) in DROPPED_ARGV
