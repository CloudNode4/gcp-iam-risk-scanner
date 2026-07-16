gcp-iam-risk-scanner

Python CLI for checking exported GCP IAM bindings

It reads a JSON file and prints a simple risk report

It is a helper for quick review

What it checks

roles owner
roles editor
allUsers
allAuthenticatedUsers
service account key users
project level service account admin

Usage

python -m gcp_iam_risk_scanner examples/iam-policy.json

or after install

gcp-iam-risk-scanner examples/iam-policy.json

Input example

The input is a normal IAM policy JSON with bindings

Notes

Use exported or mocked IAM data only
Do not commit real private data