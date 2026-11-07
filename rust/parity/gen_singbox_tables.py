#!/usr/bin/env python3
"""Generate rust/castctl-config/src/singbox_tables.rs from rust/parity/schema2.json.

schema2.json is a reflection dump of the sing-box v1.14.4 option registry
(see rust/parity/README.md for how it was produced). The generator is
deterministic. To regenerate: run the generator, then `cargo fmt` (the
generator output is not formatted on its own), and check in the diff.

    python3 rust/parity/gen_singbox_tables.py
    cargo fmt -p castctl-config

Kind mapping (schema kind + Go type -> FieldKind in singbox.rs):
  - kind uint/int with go type option.UDPNATBehavior -> UdpNatBehavior
    (string enum with a custom unmarshaler; the reflect kind lies).
  - kind int with go type option.UDPTimeoutCompat -> UdpTimeoutCompat
    (int64 seconds OR a duration string).
  - kind object with sub NetworkBytesCompat -> NetworkBytesCompat
    (hysteria up/down: network units first, then plain byte units).
  - kind object with a null-field sub that is NOT NetworkBytesCompat and
    NOT a struct table -> the field is a scalar leaf handled by the
    validator (AddrPort/Prefix are slice_struct subs, never object subs).
  - everything else maps 1:1 from the schema kind name (snake -> Pascal).
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SCHEMA = os.path.join(HERE, "schema2.json")
OUT = os.path.join(HERE, "..", "castctl-config", "src", "singbox_tables.rs")

KIND_MAP = {
    "bool": "Bool",
    "string": "Str",
    "uint": "Uint",
    "int": "Int",
    "duration": "Duration",
    "domainstrategy": "DomainStrategy",
    "networkstrategy": "NetworkStrategy",
    "fwmark": "FwMark",
    "addr": "Addr",
    "prefix": "Prefix",
    "prefixable": "Prefixable",
    "listable": "Listable",
    "slice": "Slice",
    "slice_struct": "SliceStruct",
    "object": "Object",
    "map": "Map",
    "typedmap": "TypedMap",
    "httpheader": "HttpHeader",
    "bytes": "Bytes",
    "memorybytes": "MemoryBytes",
    "networklist": "NetworkList",
    "transport": "Transport",
    "obfs": "Obfs",
    "http_client_options": "HttpClientOptions",
    "udp_over_tcp": "UdpOverTcp",
    "optimistic": "Optimistic",
    "domain_resolver": "DomainResolver",
    "dnsrcode": "DnsRcode",
    "matchresponse": "MatchResponse",
}


def rust_str(s):
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def field_kind(f):
    go = f.get("go", "")
    if go == "option.UDPNATBehavior":
        return "UdpNatBehavior"
    if go == "option.UDPTimeoutCompat":
        return "UdpTimeoutCompat"
    if f["kind"] == "object" and f.get("sub") == "NetworkBytesCompat":
        return "NetworkBytesCompat"
    return KIND_MAP[f["kind"]]


def main():
    with open(SCHEMA) as fh:
        s = json.load(fh)

    structs = s["structs"]
    # Sanity: every object/slice_struct sub must be a known struct table,
    # except the scalar leaves (AddrPort, Prefix) which have no fields.
    scalar_subs = {"AddrPort", "Prefix"}
    for name, st in structs.items():
        for f in st.get("fields") or []:
            sub = f.get("sub")
            if sub and sub not in structs and sub not in scalar_subs:
                print(f"unknown sub struct {sub} in {name}.{f['json']}", file=sys.stderr)
                return 1

    lines = []
    lines.append("// Copyright (C) 2026 castctl contributors")
    lines.append("// SPDX-License-Identifier: GPL-3.0-only")
    lines.append("")
    lines.append("//! Generated sing-box option tables (M7f). DO NOT EDIT BY HAND.")
    lines.append("//!")
    lines.append("//! Generated from `rust/parity/schema2.json` (reflection over the")
    lines.append("//! sing-box v1.14.4 option registry) by")
    lines.append("//! `rust/parity/gen_singbox_tables.py`. Regenerate with:")
    lines.append("//!")
    lines.append("//! ```sh")
    lines.append("//! python3 rust/parity/gen_singbox_tables.py")
    lines.append("//! cargo fmt -p castctl-config")
    lines.append("//! ```")
    lines.append("//!")
    lines.append("//! Field semantics (see `singbox.rs` for the validator):")
    lines.append("//! - `json`: the JSON key; `go`: the Go field type (as written in the")
    lines.append("//!   sing-box source, pointers included — the validator strips `*`")
    lines.append("//!   when rendering `UnmarshalTypeError` type names, matching Go).")
    lines.append("//! - `emb`: embedded Go field names on the path to this field,")
    lines.append("//!   innermost-first as recorded by the schema dump (the validator")
    lines.append("//!   renders them in that order in `Go struct field` paths).")
    lines.append("//! - `sub`: the struct table for `object` / `slice_struct` fields.")
    lines.append("//! - `elem`: the element Go type for `listable` / `slice` fields.")
    lines.append("//! - `key` / `val`: the key / value Go types for `typedmap` fields.")
    lines.append("")
    lines.append("use crate::singbox::FieldKind;")
    lines.append("")
    lines.append("/// One field of one sing-box option struct.")
    lines.append("#[derive(Clone, Copy, Debug)]")
    lines.append("pub struct FieldDef {")
    lines.append("    pub json: &'static str,")
    lines.append("    pub go: &'static str,")
    lines.append("    pub kind: FieldKind,")
    lines.append("    pub emb: &'static [&'static str],")
    lines.append("    pub sub: Option<&'static str>,")
    lines.append("    pub elem: Option<&'static str>,")
    lines.append("    pub key: Option<&'static str>,")
    lines.append("    pub val: Option<&'static str>,")
    lines.append("}")
    lines.append("")
    lines.append("/// One sing-box option struct: its Go type name and its fields")
    lines.append("/// in declaration order (field order only matters for the")
    lines.append("/// generated table's readability — validation follows input order).")
    lines.append("#[derive(Clone, Copy, Debug)]")
    lines.append("pub struct StructDef {")
    lines.append("    pub name: &'static str,")
    lines.append("    pub fields: &'static [FieldDef],")
    lines.append("}")
    lines.append("")

    def emit_str_list(name, values):
        lines.append(f"pub static {name}: &[&str] = &[")
        for v in values:
            lines.append(f"    {rust_str(v)},")
        lines.append("];")
        lines.append("")

    emit_str_list("OUTBOUND_TYPES", sorted(s["roots"]["outbound"]))
    emit_str_list("ENDPOINT_TYPES", sorted(s["roots"]["endpoint"]))
    emit_str_list("DNS_SERVER_TYPES", sorted(s["roots"]["dns_server"]))

    # Type -> options struct mappings (the registry dispatch tables).
    for root_name, const in (
        ("outbound", "OUTBOUND_OPTIONS"),
        ("endpoint", "ENDPOINT_OPTIONS"),
        ("dns_server", "DNS_SERVER_OPTIONS"),
    ):
        mapping = s["roots"][root_name]
        lines.append(f"/// Registry dispatch for `{root_name}`: type -> options struct.")
        lines.append(f"pub static {const}: &[(&str, &str)] = &[")
        for k in sorted(mapping):
            lines.append(f"    ({rust_str(k)}, {rust_str(mapping[k])}),")
        lines.append("];")
        lines.append("")

    for enum_name, values in sorted(s["enums"].items()):
        emit_str_list(enum_name.upper(), values)

    # Variant tables: (key, struct-or-"") pairs.
    for var_name, mapping in sorted(s["variants"].items()):
        const = var_name.upper()
        lines.append(f"/// Variant dispatch for `{var_name}`: key -> options struct")
        lines.append("/// (\"\" = no options struct; the variant takes no fields).")
        lines.append(f"pub static {const}: &[(&str, &str)] = &[")
        for k in sorted(mapping):
            lines.append(f"    ({rust_str(k)}, {rust_str(mapping[k])}),")
        lines.append("];")
        lines.append("")

    # Struct tables, sorted by name for a stable diff.
    lines.append("/// All option structs, by Go type name.")
    lines.append("pub static STRUCTS: &[StructDef] = &[")
    for name in sorted(structs):
        st = structs[name]
        fields = st.get("fields") or []
        lines.append(f"    StructDef {{ name: {rust_str(name)}, fields: &[")
        for f in fields:
            emb_raw = f.get("emb", [])
            if isinstance(emb_raw, str):
                # Schema stores embedded names dot-joined from the struct
                # root: "A.B.C" -> ["A", "B", "C"].
                emb_list = emb_raw.split(".") if emb_raw else []
            else:
                emb_list = emb_raw
            emb = ", ".join(rust_str(e) for e in emb_list)
            sub = rust_str(f["sub"]) if f.get("sub") else "None"
            sub = f"Some({sub})" if f.get("sub") else "None"
            elem = f"Some({rust_str(f['elem'])})" if f.get("elem") else "None"
            key = f"Some({rust_str(f['key'])})" if f.get("key") else "None"
            val = f"Some({rust_str(f['val'])})" if f.get("val") else "None"
            lines.append(
                "        FieldDef { json: %s, go: %s, kind: FieldKind::%s, emb: &[%s], sub: %s, elem: %s, key: %s, val: %s },"
                % (
                    rust_str(f["json"]),
                    rust_str(f["go"]),
                    field_kind(f),
                    emb,
                    sub,
                    elem,
                    key,
                    val,
                )
            )
        lines.append("    ] },")
    lines.append("];")
    lines.append("")
    lines.append("/// Look a struct table up by Go type name.")
    lines.append("pub fn struct_by_name(name: &str) -> Option<&'static StructDef> {")
    lines.append("    STRUCTS.iter().find(|s| s.name == name)")
    lines.append("}")
    lines.append("")

    with open(OUT, "w") as fh:
        fh.write("\n".join(lines))
    print(f"wrote {OUT}: {len(structs)} structs")


if __name__ == "__main__":
    main()
