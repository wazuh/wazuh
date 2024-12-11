#!/usr/bin/env python3
from health_test.test_suite import UnitResultInterface, UnitOutput, run as suite_run

class UnitResult(UnitResultInterface):
    def __init__(self, index: int, expected: dict, actual: UnitOutput, target: str, help: str):
        self.index = index
        self.expected = expected
        if not actual.success:
            self.error = actual.error
            self.success = False
        else:
            self.setup(actual.output)

    def setup(self, actual: dict):
        self.diff = {}
        if self.expected == actual:
            self.success = True
            return
        else:
            self.success = False

        for key in self.expected:
            if key not in actual:
                self.diff[key] = {"info": "Missing key in actual result",
                                  "expected": self.expected[key]}
            elif self.expected[key] != actual[key]:
                self.diff[key] = {"info": "Mismatched value",
                                  "expected": self.expected[key], "actual": actual[key]}
        for key in actual:
            if key not in self.expected:
                self.diff[key] = {"info": "Extra key in actual result",
                                  "actual": actual[key]}

def run(args):
    return suite_run(args, UnitResult, debug_mode="")
