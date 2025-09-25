import sys
from pathlib import Path


class ErrorReporter:
    def __init__(self, target):
        self.errors = {}
        self.warnings = {}
        self.target = target

    def add_error(self, integration, asset, field):
        """
        Adds a missing field error for a specific integration and asset.
        If the field has already been recorded, it won't be duplicated.
        """
        if integration not in self.errors:
            self.errors[integration] = {}

        if asset not in self.errors[integration]:
            self.errors[integration][asset] = set()

        self.errors[integration][asset].add(field)

    def has_errors(self):
        """
        Returns True if there are accumulated errors.
        """
        return bool(self.errors)

    def add_warning(self, integration, asset, message):
        """
        Adds a warning for a specific integration and asset.
        """
        if integration not in self.warnings:
            self.warnings[integration] = {}
        if asset not in self.warnings[integration]:
            self.warnings[integration][asset] = set()
        self.warnings[integration][asset].add(message)

    def has_warnings(self):
        return bool(self.warnings)

    def generate_report(self, description, base_path):
        """
        Generates a report of all accumulated errors, showing relative paths to 'integrations'.
        """
        if not self.has_errors():
            return "No errors found."

        title = getattr(self, "report_title", "Validation Report:")

        report = f"\n{title}\n"
        report += f"Failed: {description}.\n"

        base_path = Path(base_path).resolve()

        for integration, assets in self.errors.items():
            report += f"\n{self.target}: {integration}\n"
            for asset, missing_fields in assets.items():
                relative_path = Path(asset).relative_to(base_path)
                report += f"  File: {relative_path}\n"
                report += "   Fields:\n"
                for field in sorted(missing_fields):
                    report += f"    - {field}\n"
        return report

    def print_warnings(self, description, base_path):
        if not self.has_warnings():
            return
        base_path = Path(base_path).resolve()
        print("\nVALIDATION WARNINGS:")
        print(f"Warnings: {description}")
        for integration, assets in self.warnings.items():
            print(f"\n{self.target}: {integration}")
            for asset, messages in assets.items():
                relative_path = Path(asset).relative_to(base_path)
                print(f"  File: {relative_path}")
                print("   Notes:")
                for m in sorted(messages):
                    lines = str(m).splitlines()
                    if not lines:
                        continue
                    print(f"    - {lines[0]}")
                    for ln in lines[1:]:
                        print(f"      {ln}")

    def exit_with_errors(self, description, base_path):
        """
        If there are errors, generates the report and terminates the program with sys.exit(1).
        """
        if self.has_errors():
            sys.exit(self.generate_report(description, base_path))
