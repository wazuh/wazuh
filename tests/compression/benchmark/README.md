# Real-log compression study

This harness calls the production manager compressors, selected through
`ossec.conf`. It compares the behavior actually shipped by this change:
zlib's gzip default (level 6) against zstd's default (level 3), both single-threaded.
It also measures common library readback and production `manage_files()` signing
plus compression. It does not benchmark `remoted` or agent network compression.

## Privacy and inputs

Keep raw logs and source mappings outside the repository. The report generator
requires only anonymous dataset IDs, byte counts, sample offsets, hashes, and
timing observations. Never commit a transport archive or a raw corpus.

`sample_sources.py` can run as a low-priority, read-only process on a log server.
Its argument is a **private** JSON list with `path`, `size`, `mtime`,
`raw_size_hint`, `family`, and `name` for selected, closed `.gz` files. Its
stdout is a tar stream containing **real log data**, not a public report:

```sh
nice -n 15 ionice -c 3 python3 sample_sources.py private-sources.json | zstd -q -9 -T1 > private-samples.tar.zst
```

It checks gzip CRCs and stable file metadata, retains complete alert files,
and extracts three line-aligned approximately 32 MiB windows per JSON archive
(beginning, middle, end). It fails if the gzip ISIZE hint differs from the actual
uncompressed size; do not use modulo-4-GiB trailer sizes as true sizes.

For the seven-day primary study, list exactly three files per day, in order:
alert text, alert JSON, archive JSON. The collector's anonymous day numbering
assumes that layout. The embedded private manifest includes full source paths;
keep it private. Build a public `corpus/manifest.json` by removing `source` and
`source_sha256`. Each corpus file must match `sample_sha256`.

For full-file validation, supply a second corpus/manifest with complete archive
files and anonymous IDs. Match their SHA-256 to the original complete-file hash
recorded while collecting the primary samples. Do not double-count overlapping
full files in primary aggregate results.

## Build

Use a fresh Linux checkout/build with the manager dependencies and generated
FlatBuffers headers, as with a normal manager build. Avoid mixing in `TEST=1`
or sanitizer objects from unit-test builds. If the build image omits `.git`, pass
`--source-commit` to the runner explicitly.

```sh
make -C src TARGET=server deps -j4
make -C src TARGET=server -j4
cd src
make TARGET=server -f Makefile -f ../tests/compression/benchmark/Makefile compression-benchmark -j4
```

The benchmark executable uses the normal production object files and libraries.
Its metadata records the code/library versions, binary and compressor-source
hashes, compiler, kernel, CPU, affinity, memory, seed, and repeat counts.

## Run

Prepare an isolated native Linux filesystem with `corpus/manifest.json` and
the referenced corpus files. Use a fresh results directory per run. Do not
collect logs, install packages, compile, or run analysis concurrently with the
timed benchmark. Other host workloads and CPU-frequency policy are not controlled.

```sh
python3 tests/compression/benchmark/run.py \
  --root /bench --binary "$PWD/src/compression-benchmark" \
  --repeat 7 --daily-repeat 5 --cpu 2

python3 tests/compression/benchmark/run.py \
  --root /bench/full --binary "$PWD/src/compression-benchmark" \
  --repeat 3 --skip-daily --cpu 2
```

CPU 2 must exist in the container's allowed affinity set; choose an allowed CPU
explicitly for another machine. The primary production-batch fixture expects
consecutive day indices starting at 1. Use `--skip-daily` for arbitrary subsets.

The runner copies each input outside the timed interval, alternates method
order, shuffles dataset order with a fixed seed, records one excluded warm-up,
and validates restored bytes with SHA-256 after every trial. The compressors
delete only independently prepared scratch inputs. Original corpus files remain
unchanged. Batch trials likewise use disposable fixtures and verify all outputs.

Elapsed time and CPU time cover the C operation only, excluding process startup,
configuration parsing, setup, and verification. Process peak RSS uses `/proc`
VmHWM rather than inherited pre-exec `getrusage` RSS. The report includes a
configuration/library startup floor. Buffered writes are not crash-durable:
there is no `fsync`, cold-cache control, or storage-backend benchmark.

## Analyze

Install NumPy and Matplotlib outside timed runs, then:

```sh
python3 tests/compression/benchmark/report.py \
  --primary /bench/results --full /bench/full/results --output /bench/report \
  --source-version "version observed at collection"
```

Outputs include standalone HTML, Markdown, PNG/SVG figures, per-observation CSV,
per-file medians, category comparisons, environment metadata, and anonymous corpus
metadata. Bootstrap intervals describe day composition within the selected week;
they are not population-level confidence intervals for every Wazuh installation.
The stratified sample total is not a volume-weighted estimate of the full week.

Only de-identified results and code are suitable for public review. The exact
private corpus is needed to reproduce the exact numbers; the harness can also be
used with another independently prepared corpus.
