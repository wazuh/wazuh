#!/usr/bin/env python3

import subprocess
from pathlib import Path


def run_test_cases_generator():
    # Get the current directory
    current_dir = Path(__file__).resolve().parent

    # Iterate over all items in the current directory
    for item in current_dir.iterdir():
        # Check if the item is a directory
        if item.is_dir():
            # Get the list of files in the directory
            files = item.iterdir()
            # Look for files with .py extension and execute them
            for file in files:
                if file.suffix == ".py":
                    print(f"Running {file}")
                    # Execute the Python script
                    subprocess.run(["python3", str(file)])


if __name__ == "__main__":
    run_test_cases_generator()
