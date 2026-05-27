#!/usr/bin/env python3
import sys
import glob
from sigma.collection import SigmaCollection
from sigma.backends.splunk import SplunkBackend
from sigma.processing.pipeline import ProcessingPipeline, ProcessingItem
from sigma.processing.transformations import AddConditionTransformation

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
rules = SigmaCollection.load_ruleset(["detection/rules/falco/"])

if not rules:
    print("ERROR: No rules loaded", file=sys.stderr)
    sys.exit(1)

result = backend.convert(rules, "savedsearches")
print(result)