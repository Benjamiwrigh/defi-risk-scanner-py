"""
DeFi Risk Scanner
Description: Basic scanner for DeFi contracts and transactions.
Scans input data for potential risk patterns like reentrancy, selfdestruct, and unchecked external calls.
"""

import json
import re

RULES = [
    {"id": "reentrancy", "regex": r"call.value", "weight": 30, "desc": "Potential reentrancy (call.value)"},
    {"id": "selfdestruct", "regex": r"selfdestruct", "weight": 40, "desc": "Contract selfdestruct"},
    {"id": "delegatecall", "regex": r"delegatecall", "weight": 25, "desc": "Delegatecall detected"},
]

def analyze(code: str):
    risk = 0
    reasons = []
    for rule in RULES:
        if re.search(rule["regex"], code, re.IGNORECASE):
            risk += rule["weight"]
            reasons.append(rule["desc"])
    return {"risk": risk, "reasons": reasons}

if __name__ == "__main__":
    sample = "contract X { function attack() { selfdestruct(msg.sender); }}"
    report = analyze(sample)
    print(json.dumps(report, indent=2))
