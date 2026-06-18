#!/usr/bin/env python3
import sys
import glob
from sigma.collection import SigmaCollection
from sigma.backends.splunk import SplunkBackend
from sigma.processing.pipeline import ProcessingPipeline, ProcessingItem
from sigma.processing.transformations import AddConditionTransformation

SOURCES = {
    "detection/rules/falco/":       "kube:container:falco",
    "detection/rules/tetragon/":    "kube:container:tetragon",
    "detection/rules/keycloak/":    "kube:container:keycloak",
    "detection/rules/coredns/":     "kube:container:coredns",
    "detection/rules/vault/":       "kube:container:vault",
    "detection/rules/k8s-audit/":   "kube:apiserver:audit",
    "detection/rules/kube-events/": "kube:events",
}

INDICES = {
    "detection/rules/k8s-audit/": "k8s-audit",
}

all_output = []
total_rules = 0
total_dirs_skipped = 0

for rule_dir, sourcetype in SOURCES.items():
    rule_files = glob.glob(f"{rule_dir}*.yaml") + glob.glob(f"{rule_dir}*.yml")

    if not rule_files:
        print(f"DEBUG: No files found in {rule_dir}, skipping", file=sys.stderr)
        total_dirs_skipped += 1
        continue

    print(f"DEBUG: Converting {len(rule_files)} rule(s) from {rule_dir} with sourcetype={sourcetype}", file=sys.stderr)

    conditions = {"sourcetype": sourcetype}
    if rule_dir in INDICES:
        conditions["index"] = INDICES[rule_dir]

    pipeline = ProcessingPipeline(
        items=[
            ProcessingItem(
                transformation=AddConditionTransformation(conditions)
            )
        ]
    )

    backend = SplunkBackend(processing_pipeline=pipeline)

    try:
        rules = SigmaCollection.load_ruleset(rule_files)
        result = backend.convert(rules, "savedsearches")
        all_output.append(result)
        total_rules += len(rule_files)
    except Exception as e:
        print(f"ERROR: Failed to convert rules in {rule_dir}: {e}", file=sys.stderr)
        sys.exit(1)

print(f"DEBUG: Converted {total_rules} rule(s) across {len(SOURCES) - total_dirs_skipped} source(s)", file=sys.stderr)

if not all_output:
    print("ERROR: No rules converted from any source", file=sys.stderr)
    sys.exit(1)

print("\n".join(all_output))