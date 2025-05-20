import sys
from pathlib import Path


class ErrorReporter:
    def __init__(self, target):
        self.errors = {}
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

    def generate_report(self, description, base_path):
        """
        Generates a report of all accumulated errors, showing relative paths to 'integrations'.
        """
        if not self.has_errors():
            return "No errors found."

        report = "\nValidation Report:\n"
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

    def exit_with_errors(self, description, base_path):
        """
        If there are errors, generates the report and terminates the program with sys.exit(1).
        """
        if self.has_errors():
            sys.exit(self.generate_report(description, base_path))
