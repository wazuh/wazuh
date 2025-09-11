import sys
import argparse
from importlib.metadata import metadata
import yaml
try:
    from yaml import CDumper as Dumper
except ImportError:
    from yaml import Dumper
import shared.resource_handler as rs
import subprocess
from pathlib import Path, PurePath
import os
from typing import Tuple


def parse_args():
    meta = metadata('engine-suite')
    parser = argparse.ArgumentParser(
        prog='engine-diff', description='Compare two events in yaml format, returns SAME if no differences found, DIFFERENT otherwise. The script loads the events, orders them and makes a diff using delta, credits to dandavison for his awesome tool (https://github.com/dandavison/delta)')
    parser.add_argument('--version', action='version',
                        version=f'%(prog)s {meta.get("Version")}')
    parser.add_argument("fileA", help="First file to compare")
    parser.add_argument("fileB", help="Second file to compare")
    parser.add_argument("-in", "--input", help="Input format (default: json)",
                        default="json", choices=["yaml", "json"])
    parser.add_argument("-q, --quiet", help="Print only the result",
                        action="store_true", dest="quiet")
    parser.add_argument("--no-order", help="Do not order the events when comparing",
                        action="store_true", dest="no_order")

    return parser.parse_args()


def get_different_keys(dictA: dict, dictB: dict) -> Tuple[list, list]:
    missingA = []
    missingB = []

    for key in dictA:
        if key not in dictB:
            missingB.append(key)
    for key in dictB:
        if key not in dictA:
            missingA.append(key)

    return missingA, missingB

def get_different_values(dictA: dict, dictB: dict) -> list:
    differentKeyValues = []
    for key in dictA:
        if key in dictB:
            if dictA[key] != dictB[key]:
                differentKeyValues.append(key)
    return differentKeyValues


def main():
    args = parse_args()
    resource_handler = rs.ResourceHandler()

    f = rs.Format.JSON if args.input == "json" else rs.Format.YML

    fileA = args.fileA
    fileB = args.fileB

    try:
        dictA = resource_handler.load_file(fileA, f)
        dictB = resource_handler.load_file(fileB, f)
    except Exception as e:
        print(f"Error: {e}")
        return -1

    if args.no_order:
        print("SAME" if dictA == dictB else "DIFFERENT")
    else:
        orderedA = yaml.dump(dictA, sort_keys=True, Dumper=Dumper)
        orderedB = yaml.dump(dictB, sort_keys=True, Dumper=Dumper)
        print("SAME" if orderedA == orderedB else "DIFFERENT")

    if not args.quiet:
        orderedA = yaml.dump(dictA, sort_keys=True, Dumper=Dumper)
        orderedB = yaml.dump(dictB, sort_keys=True, Dumper=Dumper)

        try:
            tmpNameA = Path(fileA).stem
            tmpNameB = Path(fileB).stem

            resource_handler.save_plain_text_file(
                "/tmp/", f"{tmpNameA}_ordered.yml", orderedA)
            resource_handler.save_plain_text_file(
                "/tmp/", f"{tmpNameB}_ordered.yml", orderedB)
        except Exception as e:
            print(f"Error: {e}")
            return -1
    
        try:
            # Get different keys and values
            missingA, missingB = get_different_keys(dictA, dictB)
            differentKeyValues = get_different_values(dictA, dictB)
            if len(missingB) != 0:
                print(f"The following keys appear in {fileA} but not in {fileB}:")
                for key in missingB:
                    print(f"- {key}")
            if len(missingA) != 0:
                print(f"The following keys appear in {fileB} but not in {fileA}:")
                for key in missingA:
                    print(f"- {key}")
            if len(differentKeyValues) != 0:
                print(f"The following keys appear in both files but have different values:")
                for key in differentKeyValues:
                    print(f"- {key}")

            # Execute delta
            os.environ['DELTA_FEATURES'] = '+side-by-side delta'
            subprocess.run(["delta", f"/tmp/{tmpNameA}_ordered.yml",
                        f"/tmp/{tmpNameB}_ordered.yml"], env=os.environ)
        except Exception as e:
            print(e)
            print("Please install delta (https://github.com/dandavison/delta)")

        try:
            resource_handler.delete_file(f"/tmp/{tmpNameA}_ordered.yml")
            resource_handler.delete_file(f"/tmp/{tmpNameB}_ordered.yml")
        except Exception as e:
            pass

    return 0


if __name__ == '__main__':
    sys.exit(main())
