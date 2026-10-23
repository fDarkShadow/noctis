#!/usr/bin/env python3
"""Stage 1 — triage + score the parsed NASL candidates into a ranked shortlist.

Deterministic only (no LLM, no judgment points): drops Tier C and already-covered CVEs,
scores the objective part of fill-backlog's 15-point table (CVSS from the NASL + optional
KEV/EPSS enrichment), ranks, and writes:
  - shortlist.jsonl   (Tier A/B, uncovered, ranked desc by score then CVSS)
  - shortlist.md      (human-readable top table for picking a batch)
  - manifest.json     (created/merged; per-OID resumable state)

Claude consumes shortlist.jsonl for Stage 1b (eligibility confirmation + issue drafting).

KEV/EPSS are optional local caches so this runs offline/deterministically:
  automation/state/openvas/kev_cves.txt    one CVE id per line (CISA KEV)
  automation/state/openvas/epss.json       {"CVE-...": 0.97, ...}

Usage:
  python3 -I automation/openvas-migration/triage.py \
      --candidates automation/state/openvas/candidates.jsonl \
      --covered    automation/state/openvas/covered_cves.txt \
      --out-dir    automation/state/openvas
"""
from __future__ import annotations

import argparse
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "stage1_fill_backlog"))
sys.path.insert(0, os.path.join(_HERE, ".."))
from scoring import Candidate, deterministic_points, should_exclude, total_score  # noqa: E402


def load_lines(path: str) -> set[str]:
    if not path or not os.path.exists(path):
        return set()
    return {l.strip().upper() for l in open(path) if l.strip()}


def load_json(path: str) -> dict:
    if not path or not os.path.exists(path):
        return {}
    return json.load(open(path))


def to_candidate(rec: dict, kev: set[str], epss: dict) -> Candidate:
    cves = rec.get("cves") or []
    cve_epss = max((epss.get(c, 0.0) for c in cves), default=0.0) or None
    is_kev = any(c in kev for c in cves)
    # auth/local signal is already in the tier: B/A are remote; C is excluded upstream.
    return Candidate(
        cve_ids=cves,
        cvss=rec.get("cvss_base"),
        epss=cve_epss,
        is_kev=is_kev,
        requires_local_agent=False,
        requires_auth_session=False,
        product=(rec.get("family") or ""),
        nasl_path=rec.get("path", ""),
        summary=rec.get("summary") or "",
        is_multi_step=(rec.get("roundtrips", 0) >= 2),
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--candidates", default="automation/state/openvas/candidates.jsonl")
    ap.add_argument("--covered", default="automation/state/openvas/covered_cves.txt")
    ap.add_argument("--out-dir", default="automation/state/openvas")
    ap.add_argument("--tiers", default="A,B")
    ap.add_argument("--top", type=int, default=40)
    args = ap.parse_args()

    tiers = set(t.strip() for t in args.tiers.split(","))
    covered = load_lines(args.covered)
    kev = load_lines(os.path.join(args.out_dir, "kev_cves.txt"))
    epss = {k.upper(): float(v) for k, v in load_json(os.path.join(args.out_dir, "epss.json")).items()}

    scored = []
    for line in open(args.candidates):
        rec = json.loads(line)
        if rec["tier"] not in tiers:
            continue
        if rec["cves"] and any(c in covered for c in rec["cves"]):
            continue
        cand = to_candidate(rec, kev, epss)
        excluded, why = should_exclude(cand)
        if excluded:
            continue
        det = deterministic_points(cand)
        score = total_score(det, 0)  # judgment points added later by Claude (Stage 1b)
        rec["_score"] = score
        rec["_points"] = det
        rec["_is_kev"] = cand.is_kev
        rec["_epss"] = cand.epss
        scored.append(rec)

    scored.sort(key=lambda r: (r["_score"], r["cvss_base"] or 0, r["_is_kev"]), reverse=True)

    os.makedirs(args.out_dir, exist_ok=True)
    jl = os.path.join(args.out_dir, "shortlist.jsonl")
    with open(jl, "w") as fh:
        for r in scored:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")

    md = os.path.join(args.out_dir, "shortlist.md")
    with open(md, "w") as fh:
        fh.write(f"# OpenVAS→noctis shortlist ({len(scored)} candidates, tiers {sorted(tiers)})\n\n")
        fh.write("score (objective only; +0–4 Claude judgment added at issue time)\n\n")
        fh.write("| score | tier | cvss | kev | epss | cve(s) | family | nasl path |\n")
        fh.write("|------:|:----:|-----:|:---:|-----:|--------|--------|-----------|\n")
        for r in scored[: args.top]:
            cves = ", ".join(r["cves"][:2]) + ("…" if len(r["cves"]) > 2 else "")
            epss_s = f"{r['_epss']:.2f}" if r["_epss"] else "—"
            fh.write(f"| {r['_score']} | {r['tier']} | {r['cvss_base'] or '—'} | "
                     f"{'✓' if r['_is_kev'] else ''} | {epss_s} | {cves} | "
                     f"{(r['family'] or '')[:22]} | {r['path']} |\n")

    # resumable manifest
    man_path = os.path.join(args.out_dir, "manifest.json")
    man = load_json(man_path)
    man.setdefault("oids", {})
    added = 0
    for r in scored:
        oid = r["oid"] or r["path"]
        if oid not in man["oids"]:
            man["oids"][oid] = {"path": r["path"], "cves": r["cves"],
                                "tier": r["tier"], "score": r["_score"], "state": "triaged"}
            added += 1
    with open(man_path, "w") as fh:
        json.dump(man, fh, indent=2, ensure_ascii=False)

    print(f"shortlist: {len(scored)} candidates -> {jl}", file=sys.stderr)
    print(f"manifest: +{added} new (total {len(man['oids'])}) -> {man_path}", file=sys.stderr)
    print(f"top table -> {md}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
