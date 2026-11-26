#!/usr/bin/env python3
"""Paired benchmark of Wazuh's production gzip/zstd compressors on a private corpus."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import random
import shutil
import subprocess
import tempfile
import time


def digest_file(path):
    with open(path, "rb") as source:
        digest = hashlib.sha256()
        while block := source.read(1024 * 1024):
            digest.update(block)
        return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--repeat", type=int, default=7)
    parser.add_argument("--daily-repeat", type=int, default=5)
    parser.add_argument("--skip-daily", action="store_true")
    parser.add_argument("--cpu", type=int, default=2)
    parser.add_argument("--seed", type=int, default=20261116)
    parser.add_argument("--source-commit", help="Source revision when the build image omits .git")
    args = parser.parse_args()
    root, binary = args.root.resolve(), args.binary.resolve()
    revision = subprocess.run(["git", "-C", str(binary.parents[1]), "rev-parse", "HEAD"],
                              text=True, capture_output=True)
    source_commit = args.source_commit or (revision.stdout.strip() if revision.returncode == 0 else "not recorded")
    os.sched_setaffinity(0, {args.cpu})
    corpus = root / "corpus"
    datasets = json.loads((corpus / "manifest.json").read_text())
    for item in datasets:
        assert Path(item["filename"]).name == item["filename"]
        assert digest_file(corpus / item["filename"]) == item["sample_sha256"]
    work, results, runtime = root / "work", root / "results", root / "runtime"
    for path in (work, results, runtime / "etc", runtime / "logs"):
        path.mkdir(parents=True, exist_ok=True)
    shutil.copy(binary.parents[1] / "etc/internal_options.conf", runtime / "etc/internal_options.conf")
    for algorithm in ("gzip", "zstd"):
        (runtime / "etc" / f"{algorithm}.conf").write_text(
            f"<ossec_config><global><compression_method>{algorithm}</compression_method></global></ossec_config>")
    environment = dict(os.environ, LD_LIBRARY_PATH=str(binary.parent))
    environment.pop("LD_PRELOAD", None)
    rng = random.Random(args.seed)
    raw_path = results / "trials.jsonl"
    assert not raw_path.exists(), "Use a fresh results directory to avoid mixing runs"

    def invoke(algorithm, operation, source, destination=None, home=runtime):
        command = [str(binary), str(home), str(runtime / "etc" / f"{algorithm}.conf"), operation, str(source)]
        if destination is not None:
            command.append(str(destination))
        result = subprocess.run(command, text=True, capture_output=True, env=environment, check=True)
        metrics = json.loads(result.stdout.strip().splitlines()[-1])
        assert metrics["result"] == 0
        metrics["cpu_s"] = metrics["user_s"] + metrics["system_s"]
        return metrics

    def record(metrics):
        with raw_path.open("a") as target:
            target.write(json.dumps(metrics, sort_keys=True) + "\n")

    def verify_compressed(path, algorithm, expected):
        digest = hashlib.sha256()
        if algorithm == "gzip":
            with gzip.open(path, "rb") as stream:
                while block := stream.read(1024 * 1024):
                    digest.update(block)
        else:
            process = subprocess.Popen(["zstd", "-dq", "-c", str(path)], stdout=subprocess.PIPE)
            while block := process.stdout.read(1024 * 1024):
                digest.update(block)
            assert process.wait() == 0
        assert digest.hexdigest() == expected

    for algorithm in ("gzip", "zstd"):
        record(dict(invoke(algorithm, "baseline", "unused"), dataset="startup", kind="startup", day=0,
                    repetition=0, warmup=True, raw_bytes=0, compressed_bytes=0, verified=True))

    # Each dataset/algorithm receives one unmeasured, verified warm-up.
    sizes = {}
    started = time.time()
    for repetition in range(args.repeat + 1):
        order = list(datasets)
        rng.shuffle(order)
        for index, item in enumerate(order):
            algorithms = ["gzip", "zstd"] if (index + repetition) % 2 == 0 else ["zstd", "gzip"]
            for algorithm in algorithms:
                with tempfile.TemporaryDirectory(dir=work, prefix="file-") as name:
                    scratch = Path(name)
                    source, restored = scratch / "payload", scratch / "restored"
                    shutil.copyfile(corpus / item["filename"], source)
                    metrics = invoke(algorithm, "compress", source)
                    compressed = Path(str(source) + (".gz" if algorithm == "gzip" else ".zst"))
                    assert compressed.exists() and not source.exists()
                    size = compressed.stat().st_size
                    key = item["id"], algorithm
                    assert sizes.setdefault(key, size) == size, "Non-deterministic compressed size"
                    readback = invoke(algorithm, "decompress", compressed, restored)
                    assert digest_file(restored) == item["sample_sha256"]
                    common = {"dataset": item["id"], "kind": item["kind"], "day": item["day"],
                              "repetition": repetition, "warmup": repetition == 0,
                              "raw_bytes": item["sample_bytes"], "compressed_bytes": size, "verified": True}
                    record(dict(metrics, **common))
                    record(dict(readback, **common))
        print(f"File round {repetition}/{args.repeat} complete ({time.time()-started:.1f}s)", flush=True)

    # Production manage_files(): signing plus compression of all 21 files.
    for repetition in range(0 if args.skip_daily else args.daily_repeat + 1):
        algorithms = ["gzip", "zstd"] if repetition % 2 == 0 else ["zstd", "gzip"]
        for algorithm in algorithms:
            with tempfile.TemporaryDirectory(dir=work, prefix="daily-") as name:
                home = Path(name)
                (home / "etc").symlink_to(runtime / "etc", target_is_directory=True)
                for folder in ("alerts", "archives", "firewall"):
                    (home / "logs" / folder / "2026/Nov").mkdir(parents=True)
                outputs = []
                for item in sorted(datasets, key=lambda value: value["day"]):
                    folder = "archives" if item["kind"] == "archives-json" else "alerts"
                    tag = "archive" if folder == "archives" else "alerts"
                    extension = "log" if item["kind"] == "alerts-log" else "json"
                    suffix = "" if item["day"] == 1 else f"-{item['day']-1:03d}"
                    path = home / "logs" / folder / "2026/Nov" / f"ossec-{tag}-15{suffix}.{extension}"
                    shutil.copyfile(corpus / item["filename"], path)
                    outputs.append((path, item))
                metrics = invoke(algorithm, "daily", "unused", home=home)
                total = 0
                for path, item in outputs:
                    compressed = Path(str(path) + (".gz" if algorithm == "gzip" else ".zst"))
                    assert not path.exists() and compressed.exists()
                    total += compressed.stat().st_size
                    verify_compressed(compressed, algorithm, item["sample_sha256"])
                assert total == sum(value for (dataset, method), value in sizes.items() if method == algorithm)
                assert len(list((home / "logs").glob("**/*.sum"))) >= 3
                record(dict(metrics, dataset="all", kind="all", day=0, repetition=repetition,
                            warmup=repetition == 0, raw_bytes=sum(x["sample_bytes"] for x in datasets),
                            compressed_bytes=total, verified=True))
        print(f"Daily round {repetition}/{args.daily_repeat} complete ({time.time()-started:.1f}s)", flush=True)

    def output(command):
        return subprocess.check_output(command, text=True).strip()

    metadata = {"source_commit": source_commit,
                "binary_sha256": digest_file(binary), "driver_sha256": digest_file(Path(__file__).with_name("driver.c")),
                "compiler": output(["gcc", "-dumpfullversion"]), "uname": output(["uname", "-srmo"]),
                "cpu_info": json.loads(output(["lscpu", "-J"])), "logical_cpus": os.cpu_count(),
                "affinity": sorted(os.sched_getaffinity(0)), "page_size": os.sysconf("SC_PAGE_SIZE"),
                "memory_bytes": os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES"),
                "repeat": args.repeat, "daily_repeat": 0 if args.skip_daily else args.daily_repeat, "seed": args.seed,
                "started_unix": started, "elapsed_s": time.time() - started,
                "cache_policy": "warm cache; untimed independent input copy before each timed compressor",
                "durability": "buffered writes; no fsync or global cache dropping",
                "rss_definition": "/proc/self/status VmHWM of executed C driver, including startup/configuration; excludes inherited Python pre-exec peak",
                "gzip_level": "zlib default (-1, equivalent to level 6)", "zstd_level": 3,
                "codec_files_sha256": {name: digest_file(binary.parent / "monitord" / name)
                                       for name in ("compress_log.c", "compress_zstd.c")}}
    (results / "environment.json").write_text(json.dumps(metadata, indent=2) + "\n")
    shutil.copy(corpus / "manifest.json", results / "corpus.json")
    print("All timed and warm-up results passed SHA-256 readback verification", flush=True)


if __name__ == "__main__":
    main()
