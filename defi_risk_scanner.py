# File: defi_risk_scanner.py
# Description: Scores a wallet's risk using heuristics on transfer logs,
# protocol interactions and temporal patterns. Can read a local CSV/JSON
# export or stdin. Emits score 0..100 and flags with explanations.
# Usage: python3 defi_risk_scanner.py --input history.json --address 0xabc...

import argparse, json, sys, math, csv, statistics as stats
from collections import defaultdict, Counter
from datetime import datetime, timezone

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--input", required=True, help="CSV or JSON of txs")
    p.add_argument("--address", required=True)
    p.add_argument("--out", default="-")
    return p.parse_args()

def load_rows(path):
    if path.endswith(".json"):
        data = json.load(open(path))
        if isinstance(data, dict) and "txs" in data: data = data["txs"]
        return data
    # CSV fallback
    with open(path, newline="") as f:
        return list(csv.DictReader(f))

def to_int(x, default=0):
    try:
        return int(x)
    except Exception:
        try:
            return int(float(x))
        except Exception:
            return default

def iso(ts):
    try:
        return datetime.fromtimestamp(int(ts), tz=timezone.utc).isoformat()
    except Exception:
        return str(ts)

def normalize(rows, addr):
    out = []
    for r in rows:
        out.append({
            "hash": r.get("hash") or r.get("txHash") or "",
            "from": (r.get("from") or r.get("src") or "").lower(),
            "to": (r.get("to") or r.get("dst") or "").lower(),
            "method": (r.get("method") or r.get("functionName") or "").lower(),
            "token": (r.get("tokenSymbol") or r.get("symbol") or "").upper(),
            "value": float(r.get("value") or r.get("amount") or 0) or 0.0,
            "time": to_int(r.get("timeStamp") or r.get("timestamp") or r.get("time") or 0)
        })
    # keep only relevant time-sorted
    out.sort(key=lambda r: r["time"])
    return out

SUS_METHODS = {"permit", "increaseallowance", "setapprovalforall", "permit2"}
MIXERS = {"0x5ace...", "0x1111..."}  # extend list offline
PHISHING_TOKENS = {"FAKE", "SCAM"}

def score(rows, addr):
    addr = addr.lower()
    flags = []
    points = 0.0

    if not rows:
        return 10.0, ["no history"]

    # 1) Mixer proximity & sudden inflow spikes
    from_mixers = [r for r in rows if r["from"] in MIXERS and r["to"] == addr]
    if from_mixers:
        flags.append(f"received from known mixer: {len(from_mixers)} txs")
        points += 35

    # 2) Unlimited approvals / sensitive methods
    approvals = sum(1 for r in rows if r["from"] == addr and any(m in r["method"] for m in SUS_METHODS))
    if approvals > 0:
        points += min(25, approvals * 5)
        flags.append(f"sensitive approvals: {approvals}")

    # 3) Burst activity heuristic (micro-timestamp spacing)
    gaps = [rows[i+1]["time"] - rows[i]["time"] for i in range(len(rows)-1)]
    if gaps:
        q1 = stats.quantiles(gaps, n=4)[0]
        bursts = sum(1 for g in gaps if g <= max(10, q1/5))
        if bursts >= 3:
            flags.append(f"bot-like bursts: {bursts}")
            points += 10

    # 4) Suspicious tokens
    bad_tokens = [r for r in rows if r["token"] in PHISHING_TOKENS and r["to"] == addr]
    if bad_tokens:
        flags.append(f"received suspicious tokens: {len(bad_tokens)}")
        points += 10

    # 5) Wash patterns (back-and-forth)
    pair_counts = Counter((r["from"], r["to"]) for r in rows)
    for (a, b), c in pair_counts.items():
        if a==addr or b==addr:
            rev = pair_counts.get((b, a), 0)
            if c >= 3 and rev >= 3:
                flags.append(f"wash-like transfers between {a} and {b}")
                points += 15
                break

    # 6) Cold wallet bonus
    recent = [r for r in rows if (rows[-1]["time"] - r["time"]) < 30*24*3600]
    if not recent:
        flags.append("no recent activity (cold wallet)")
        points = max(0, points - 10)

    # Normalize to 0..100
    score = round(max(0.0, min(100.0, points)), 2)
    return score, flags

def main():
    args = parse_args()
    rows_raw = load_rows(args.input)
    rows = normalize(rows_raw, args.address)
    s, flags = score(rows, args.address)
    report = {
        "address": args.address,
        "score": s,
        "flags": flags,
        "total_txs": len(rows),
        "last_tx": iso(rows[-1]["time"]) if rows else None
    }
    out = json.dumps(report, indent=2)
    (sys.stdout if args.out == "-" else open(args.out, "w")).write(out + ("\n" if not out.endswith("\n") else ""))

if __name__ == "__main__":
    main()
