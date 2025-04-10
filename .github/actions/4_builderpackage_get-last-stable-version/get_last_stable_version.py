#! /usr/bin/env python3
# -*- coding: utf-8 -*-
"""Module providing a function to get the last stable version for a given 
owner, repository and target_version combination.
"""
import argparse
import requests
from packaging import version

def get_previous_stable_version(owner: str, repository: str,
                               target_version: str) -> str | None:
    """Returns the previous stable version for the given arguments.
    Args:
        owner: (str): Repository owner.
        repository: (str): Repository name.
        target_version: (str): Version on the basis of which we are looking for
          the most recent previous stable version.
    Returns:
        ver: (str): Most recent stable version.
    """
    url = f"https://api.github.com/repos/{owner}/{repository}/releases"
    try:
        # Get GitHub releases
        response = requests.get(url, timeout=20)
        response.raise_for_status()
        releases = response.json()

        # Extract stable versions
        stable_versions = []
        for release in releases:
            tag = release['tag_name']
            if not any(x in tag for x in ['-alpha', '-rc', '-beta']):
                try:
                    ver = version.parse(tag[1:])  # Remove initial 'v'
                    stable_versions.append(ver)
                except version.InvalidVersion:
                    continue

        # Sort versions
        stable_versions.sort(reverse=True)

        target_ver = version.parse(target_version)

        # Find the first version lower than the target
        for ver in stable_versions:
            if ver < target_ver:
                return str(ver)

        return None

    except requests.Timeout:
        print("Error: Request timed out.")

    except requests.RequestException as e:
        print(f"Request error: {e}")

def main():
    """Main function."""
    script_description = (
        "Get the last stable version for a given owner, repository and \
        target_version combination."
    )

    parser = argparse.ArgumentParser(description=script_description)
    parser.add_argument("-o", "--owner", type=str, action="store",
                        required=True, help="Repository owner.")
    parser.add_argument("-r",  "--repository", type=str, action="store",
                        required=True, help="Repository name.")
    parser.add_argument("-v", "--version", type=str, action="store",
                        required=True, help="Base version.")

    args = parser.parse_args()

    print(get_previous_stable_version(args.owner, args.repository,
                                       args.version))

if __name__ == "__main__":
    main()
