#!/usr/bin/env python3
from health_test.test_suite import UnitResultInterface, UnitOutput, run as suite_run

class UnitResult(UnitResultInterface):
    def __init__(self, index: int, expected: dict, actual: UnitOutput, target: str, help: str):
        self.index = index
        self.expected = expected
        self.success = actual.success
        self.target = target
        self.diff = {}

        if not self.success:
            self.error = actual.error
            return

        self.expected_decoders = expected.get('wazuh', {}).get('decoders', [])
        self.expected_rules = expected.get('wazuh', {}).get('rules', [])

        self.success_decoders = []
        self.success_rules = []

        self.setup(actual.output)
        self.check_missing_or_extra_assets()

    def setup(self, actual_output: dict):
        traces = actual_output.get('traces', [])

        for t in traces:
            asset = t.get('asset')
            success = t.get('success', False)

            if not success:
                continue

            try:
                asset_type, name, _version = asset.split('/')
            except ValueError:
                self.diff[self.index] = {
                    "info": "Invalid asset format",
                    "asset": asset
                }
                self.success = False
                continue

            if asset_type == 'decoder':
                self.success_decoders.append(name)

            elif asset_type == 'rule':
                self.success_rules.append(name)

    def check_missing_or_extra_assets(self):
        missing_decoders = [d for d in self.expected_decoders if d not in self.success_decoders]
        extra_decoders = [d for d in self.success_decoders if d not in self.expected_decoders]

        if self.target == 'decoder':
            if missing_decoders and extra_decoders:
                self.diff.setdefault(self.index, {}).setdefault("decoders", {}).update({
                    "status": "Mismatch detected",
                    "decoders_not_found": missing_decoders,
                    "decoders_not_added": extra_decoders
                })
                self.success = False
            elif missing_decoders:
                self.diff.setdefault(self.index, {}).setdefault("decoders", {}).update({
                    "status": "Decoders that did not appear in the trace",
                    "decoders_not_found": missing_decoders
                })
                self.success = False
            elif extra_decoders:
                self.diff.setdefault(self.index, {}).setdefault("decoders", {}).update({
                    "status": "Decoders that were successful in tracing and were not added",
                    "decoders_not_added": extra_decoders
                })
                self.success = False
        else:
            missing_rules = [r for r in self.expected_rules if r not in self.success_rules]
            extra_rules = [r for r in self.success_rules if r not in self.expected_rules]

            if missing_rules and extra_rules:
                self.diff.setdefault(self.index, {}).setdefault("rules", {}).update({
                    "status": "Mismatch detected",
                    "rules_not_found": missing_rules,
                    "rules_not_added": extra_rules
                })
                self.success = False
            elif missing_rules:
                self.diff.setdefault(self.index, {}).setdefault("rules", {}).update({
                    "status": "Rules that did not appear in the trace",
                    "rules_not_found": missing_rules
                })
                self.success = False
            elif extra_rules:
                self.diff.setdefault(self.index, {}).setdefault("rules", {}).update({
                    "status": "Rules that were successful in tracing and were not added",
                    "rules_not_added": extra_rules
                })
                self.success = False


def run(args):
    return suite_run(args, UnitResult, debug_mode="-d")
