import argparse
import json
from pathlib import Path

BAD_ROLES = {
    "roles/owner": "high",
    "roles/editor": "high",
    "roles/iam.serviceAccountAdmin": "medium",
    "roles/iam.serviceAccountKeyAdmin": "high",
    "roles/iam.serviceAccountUser": "medium",
}

PUBLIC_MEMBERS = {"allUsers", "allAuthenticatedUsers"}


def load_policy(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def member_name(member: str) -> str:
    if ":" in member:
        return member.split(":", 1)[1]
    return member


def scan(policy: dict) -> list[dict]:
    findings = []
    bindings = policy.get("bindings", [])

    for item in bindings:
        role = item.get("role", "")
        members = item.get("members", [])

        if role in BAD_ROLES:
            findings.append({
                "risk": BAD_ROLES[role],
                "title": f"Broad role used: {role}",
                "details": f"Members: {', '.join(members) or 'none'}",
            })

        for member in members:
            if member in PUBLIC_MEMBERS:
                findings.append({
                    "risk": "high",
                    "title": f"Public member used in {role}",
                    "details": member,
                })

            clean = member_name(member)
            if clean.endswith("gserviceaccount.com") and role == "roles/owner":
                findings.append({
                    "risk": "high",
                    "title": "Service account has owner role",
                    "details": clean,
                })

    return findings


def print_report(path: Path, findings: list[dict]) -> None:
    print("GCP IAM risk report")
    print(f"File: {path}")
    print("")

    if not findings:
        print("No risky IAM binding found")
        return

    counts = {"high": 0, "medium": 0, "low": 0}
    for finding in findings:
        counts[finding["risk"]] = counts.get(finding["risk"], 0) + 1

    print(f"Findings: {len(findings)}")
    print(f"High: {counts['high']}")
    print(f"Medium: {counts['medium']}")
    print("")

    for finding in findings:
        print(f"[{finding['risk'].upper()}] {finding['title']}")
        print(f"  {finding['details']}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("file", help="IAM policy JSON file")
    args = parser.parse_args()

    path = Path(args.file)
    policy = load_policy(path)
    findings = scan(policy)
    print_report(path, findings)


if __name__ == "__main__":
    main()
