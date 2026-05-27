#!/usr/bin/env python3
import sys
import glob
from sigma.collection import SigmaCollection
from sigma.backends.splunk import SplunkBackend
from sigma.processing.pipeline import ProcessingPipeline, ProcessingItem
from sigma.processing.transformations import AddConditionTransformation

rule_files = glob.glob("detection/rules/falco/*.yaml") + glob.glob("detection/rules/falco/*.yml")

print(f"DEBUG: Found files: {rule_files}", file=sys.stderr)

if not rule_files:
    print("ERROR: No rule files found at detection/rules/falco/", file=sys.stderr)
    sys.exit(1)

pipeline = ProcessingPipeline(
    items=[
        ProcessingItem(
            transformation=AddConditionTransformation(
                {"sourcetype": "kube:container:falco"}
            )
        )
    ]
)

backend = SplunkBackend(processing_pipeline=pipeline)
rules = SigmaCollection.load_ruleset(rule_files)
print(f"DEBUG: Rules loaded: {len(rules)}", file=sys.stderr)

result = backend.convert(rules, "savedsearches")
print(result)