#!/usr/bin/env python3
"""Live-cluster gates for the content manager's query shape.

Two properties of the in-PIT consistency model cannot be asserted against a fake, because the fake
is not what would reject them -- OpenSearch is. Both are cheap to check against a real cluster and
neither needs the project to be built: they are pure query-shape questions, issued straight at the
REST API.

  1. **The cursor sort survives a cold start.** Validating consumer readiness from inside the
     snapshot means the PIT spans `.wazuh-cti-consumers` as well as the data indices, and that index
     does not map `offset`. Running this against a real cluster corrected the reasoning it was
     written from: OpenSearch requires a sort field to be mapped in *at least one* index of the
     search, not in every one, so the consumer index alone is harmless. What is NOT harmless is a
     fresh install, where the data index has no documents and therefore no dynamic mapping for the
     cursor field either -- now it is unmapped everywhere, OpenSearch rejects the whole search, and
     the first feed load of a new manager fails. `FactoryContentUpdater::buildSort` injects
     `unmapped_type`, and this asserts both halves: rejected without it, accepted with it.

  2. **Slicing over that PIT neither loses nor duplicates documents.** PIT slicing is shard-derived,
     so adding the consumer index changes how `{"id": i, "max": n}` partitions the data. Correctness
     does not depend on even distribution -- the two-sided consumer-document filter handles that --
     but it does depend on the slices summing to exactly the corpus. Skew is reported rather than
     asserted, since it is a performance property, not a correctness one.

Standard library only, so it runs anywhere Python 3 does.

Usage:
    docker compose -f docker-compose.yml up -d
    ./query_contract_test.py [--host http://localhost:9400]
    docker compose -f docker-compose.yml down -v
"""

import argparse
import json
import sys
import time
import urllib.error
import urllib.request

# Index names are the shapes under test, not the production ones: the point is the mapping
# relationship between them, and a test that wrote to real index names could not be pointed at a
# cluster that had any.
DATA_INDEX = "cmtest-threatintel-data"
CONSUMER_INDEX = "cmtest-cti-consumers"
CONSUMER_ID = "cti:catalog:consumer:test"

DATA_SHARDS = 3
DOCUMENT_COUNT = 120

# Exactly what FactoryContentUpdater::buildSort emits for a cursor-mode topic whose PIT includes a
# consumer status index. Kept literal, and kept next to the negative control below, so the thing
# this gate protects is visible in one place.
VD_SORT_WITH_UNMAPPED_TYPE = [{"offset": {"order": "asc", "unmapped_type": "long"}}, {"_id": "asc"}]
VD_SORT_WITHOUT_UNMAPPED_TYPE = [{"offset": "asc"}, {"_id": "asc"}]

# What the Engine's topics sort on. `_shard_doc` is synthesised by the PIT itself, so it is mapped
# in every index the PIT spans and needs no `unmapped_type` -- this gate proves that claim rather
# than trusting it.
ENGINE_SORT = [{"_shard_doc": "asc"}, {"_id": "asc"}]


class Failure(Exception):
    """A gate that did not hold."""


def request(host, method, path, body=None, expect_status=True):
    """Issue one request. Returns (status, parsed-body-or-None)."""
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        url=f"{host}{path}",
        data=data,
        method=method,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            payload = response.read()
            return response.status, (json.loads(payload) if payload else None)
    except urllib.error.HTTPError as error:
        payload = error.read()
        parsed = None
        if payload:
            try:
                parsed = json.loads(payload)
            except json.JSONDecodeError:
                parsed = {"raw": payload.decode(errors="replace")}
        if expect_status:
            return error.code, parsed
        raise
    except urllib.error.URLError as error:
        raise Failure(f"cannot reach {host}: {error.reason}") from error


def wait_for_cluster(host, timeout_seconds=120):
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        try:
            status, body = request(host, "GET", "/_cluster/health?wait_for_status=yellow&timeout=5s")
            if status == 200 and body.get("status") in ("yellow", "green"):
                return
        except Failure:
            pass
        time.sleep(2)
    raise Failure(
        f"cluster at {host} did not become ready within {timeout_seconds}s. "
        "Start one with: docker compose -f docker-compose.yml up -d"
    )


def seed(host):
    """Build the mapping relationship the gates are about: a data index that maps `offset`, and a
    consumer index that deliberately does not."""
    for index in (DATA_INDEX, CONSUMER_INDEX):
        request(host, "DELETE", f"/{index}")

    request(
        host,
        "PUT",
        f"/{DATA_INDEX}",
        {
            "settings": {"index": {"number_of_shards": DATA_SHARDS, "number_of_replicas": 0}},
            "mappings": {"properties": {"offset": {"type": "long"}, "type": {"type": "keyword"}}},
        },
    )

    # `local_offset`, NOT `offset`. This asymmetry is the entire reason `unmapped_type` exists, and
    # it mirrors the real `.wazuh-cti-consumers` mapping.
    request(
        host,
        "PUT",
        f"/{CONSUMER_INDEX}",
        {
            "settings": {"index": {"number_of_shards": 1, "number_of_replicas": 0}},
            "mappings": {"properties": {"local_offset": {"type": "long"}, "status": {"type": "keyword"}}},
        },
    )

    bulk = []
    for i in range(1, DOCUMENT_COUNT + 1):
        bulk.append(json.dumps({"index": {"_index": DATA_INDEX, "_id": f"CVE-{i:05d}"}}))
        bulk.append(json.dumps({"offset": i, "type": "CVE"}))
    bulk.append(json.dumps({"index": {"_index": CONSUMER_INDEX, "_id": CONSUMER_ID}}))
    bulk.append(json.dumps({"status": "ready", "local_offset": DOCUMENT_COUNT}))

    payload = "\n".join(bulk) + "\n"
    req = urllib.request.Request(
        url=f"{host}/_bulk?refresh=wait_for",
        data=payload.encode(),
        method="POST",
        headers={"Content-Type": "application/x-ndjson"},
    )
    with urllib.request.urlopen(req, timeout=60) as response:
        result = json.loads(response.read())
    if result.get("errors"):
        raise Failure(f"seeding failed: {json.dumps(result)[:500]}")


def open_pit(host):
    status, body = request(host, "POST", f"/{DATA_INDEX},{CONSUMER_INDEX}/_search/point_in_time?keep_alive=5m")
    if status != 200:
        raise Failure(f"could not open a PIT over both indices: {body}")
    return body["pit_id"]


def close_pit(host, pit_id):
    request(host, "DELETE", "/_search/point_in_time", {"pit_id": pit_id})


def search(host, pit_id, sort, size=10, slice_spec=None, query=None):
    body = {
        "size": size,
        "query": query if query is not None else {"match_all": {}},
        "sort": sort,
        "pit": {"id": pit_id, "keep_alive": "5m"},
    }
    if slice_spec is not None:
        body["slice"] = slice_spec
    return request(host, "POST", "/_search", body)


def gate_sort_works_in_steady_state(host):
    """Gate 1a: the sort the factory emits is accepted once the data index has content.

    Worth stating what this does NOT show, because the module's own comments used to claim it did:
    the consumer index lacking `offset` is, on its own, harmless. OpenSearch requires a sort field to
    be mapped in *at least one* index of the search, not in every one; documents from the indices
    that lack it simply sort as missing. The un-injected form passes here too -- see gate 1b for the
    case where it does not.
    """
    pit_id = open_pit(host)
    try:
        status, body = search(host, pit_id, VD_SORT_WITH_UNMAPPED_TYPE)
        if status != 200:
            raise Failure(
                "the sort the factory emits was REJECTED by the cluster. Every cycle of every "
                f"cursor-mode topic would fail. Response: {json.dumps(body)[:600]}"
            )

        status_engine, body_engine = search(host, pit_id, ENGINE_SORT)
        if status_engine != 200:
            raise Failure(
                "_shard_doc is not usable over a PIT spanning both indices, so the Engine's topics "
                f"cannot sort at all. Response: {json.dumps(body_engine)[:600]}"
            )

        return f"{DATA_SHARDS} data shards + 1 consumer shard; _shard_doc usable too"
    finally:
        close_pit(host, pit_id)


def gate_cursor_sort_survives_a_cold_start(host):
    """Gate 1b: the one `unmapped_type` is actually load-bearing for.

    A fresh install has a data index with no documents in it yet, so the cursor field has no dynamic
    mapping -- and *now* the field is unmapped across every index in the PIT, which OpenSearch does
    reject. That is precisely the cold start on which the vulnerability scanner performs its first
    full load, so without the injection the very first cycle of a new manager fails, and so does
    every cycle after it until something else creates the mapping.

    The negative control is the point of this gate: it proves the injection is doing work.
    """
    empty_index = f"{DATA_INDEX}-cold"
    request(host, "DELETE", f"/{empty_index}")
    request(
        host,
        "PUT",
        f"/{empty_index}",
        {
            "settings": {"index": {"number_of_shards": 1, "number_of_replicas": 0}},
            # No `offset`: exactly what a data index looks like before its first document lands.
            "mappings": {"properties": {"type": {"type": "keyword"}}},
        },
    )

    status, body = request(
        host, "POST", f"/{empty_index},{CONSUMER_INDEX}/_search/point_in_time?keep_alive=5m"
    )
    if status != 200:
        raise Failure(f"could not open a cold-start PIT: {body}")
    pit_id = body["pit_id"]

    try:
        status_without, _ = search(host, pit_id, VD_SORT_WITHOUT_UNMAPPED_TYPE)
        if status_without == 200:
            raise Failure(
                "the sort WITHOUT unmapped_type was accepted even on a cold start. This gate can no "
                "longer detect the regression it exists for -- either this cluster version stopped "
                "rejecting fully-unmapped sort keys, or the fixture is no longer reproducing a "
                "cold start."
            )

        status_with, body_with = search(host, pit_id, VD_SORT_WITH_UNMAPPED_TYPE)
        if status_with != 200:
            raise Failure(
                "the injected sort was rejected on a cold start, so a fresh manager could never "
                f"perform its first feed load. Response: {json.dumps(body_with)[:600]}"
            )

        return "rejected without unmapped_type, accepted with it"
    finally:
        close_pit(host, pit_id)
        request(host, "DELETE", f"/{empty_index}")


def gate_consumer_documents_are_excluded(host):
    """The query-side half of the two-sided defence: `must_not` on the `_index` metafield.

    Not one of the original three, but it costs one request on a PIT that is already open and it is
    the other thing that only a real cluster can confirm -- `_index` matching is exactly where an
    alias would silently stop matching.
    """
    pit_id = open_pit(host)
    try:
        scoped = {
            "bool": {
                "must": [{"match_all": {}}],
                "must_not": [{"terms": {"_index": [CONSUMER_INDEX]}}],
            }
        }
        status, body = search(host, pit_id, ENGINE_SORT, size=500, query=scoped)
        if status != 200:
            raise Failure(f"the scoped query was rejected: {json.dumps(body)[:600]}")

        hits = body["hits"]["hits"]
        leaked = [hit["_id"] for hit in hits if hit["_index"] == CONSUMER_INDEX]
        if leaked:
            raise Failure(f"consumer documents reached the results despite the must_not: {leaked}")
        if len(hits) != DOCUMENT_COUNT:
            raise Failure(f"expected {DOCUMENT_COUNT} data documents, got {len(hits)}")

        return f"{len(hits)} data documents, 0 consumer documents"
    finally:
        close_pit(host, pit_id)


def gate_slicing_neither_loses_nor_duplicates(host, slices=2):
    """Gate 2."""
    pit_id = open_pit(host)
    try:
        seen = {}
        per_slice = []
        for slice_id in range(slices):
            collected = []
            search_after = None
            while True:
                body = {
                    "size": 10,
                    "query": {
                        "bool": {
                            "must": [{"match_all": {}}],
                            "must_not": [{"terms": {"_index": [CONSUMER_INDEX]}}],
                        }
                    },
                    "sort": ENGINE_SORT,
                    "pit": {"id": pit_id, "keep_alive": "5m"},
                    "slice": {"id": slice_id, "max": slices},
                }
                if search_after is not None:
                    body["search_after"] = search_after
                status, response = request(host, "POST", "/_search", body)
                if status != 200:
                    raise Failure(
                        f"sliced search failed for slice {slice_id}/{slices}: {json.dumps(response)[:600]}"
                    )
                hits = response["hits"]["hits"]
                if not hits:
                    break
                for hit in hits:
                    collected.append(hit["_id"])
                    seen[hit["_id"]] = seen.get(hit["_id"], 0) + 1
                if len(hits) < 10:
                    break
                search_after = hits[-1]["sort"]
            per_slice.append(len(collected))

        duplicated = sorted(doc for doc, count in seen.items() if count > 1)
        if duplicated:
            raise Failure(f"{len(duplicated)} document(s) were delivered by more than one slice: {duplicated[:5]}")
        if len(seen) != DOCUMENT_COUNT:
            missing = DOCUMENT_COUNT - len(seen)
            raise Failure(f"{missing} document(s) were delivered by no slice at all")

        # Returned, not asserted: uneven slices cost wall-clock, not correctness, and the split is
        # shard-derived, so it legitimately changes with the cluster's shape.
        return per_slice
    finally:
        close_pit(host, pit_id)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", default="http://localhost:9400", help="OpenSearch REST endpoint")
    parser.add_argument("--slices", type=int, default=2, help="slice count for the slicing gate")
    parser.add_argument("--keep", action="store_true", help="leave the test indices behind for inspection")
    args = parser.parse_args()

    print(f"content-manager query contract gates against {args.host}")

    try:
        wait_for_cluster(args.host)
        seed(args.host)

        detail = gate_sort_works_in_steady_state(args.host)
        print(f"  PASS  the emitted sort works over a PIT spanning both indices — {detail}")

        detail = gate_cursor_sort_survives_a_cold_start(args.host)
        print(f"  PASS  unmapped_type saves the cold-start sort — {detail}")

        detail = gate_consumer_documents_are_excluded(args.host)
        print(f"  PASS  consumer documents are excluded query-side — {detail}")

        per_slice = gate_slicing_neither_loses_nor_duplicates(args.host, args.slices)
        spread = f"{min(per_slice)}..{max(per_slice)}"
        print(
            f"  PASS  slicing neither loses nor duplicates — {DOCUMENT_COUNT} documents across "
            f"{args.slices} slices, per-slice {per_slice} (spread {spread}; skew is a performance "
            f"property, not asserted)"
        )

    except Failure as failure:
        print(f"  FAIL  {failure}", file=sys.stderr)
        return 1
    finally:
        if not args.keep:
            for index in (DATA_INDEX, CONSUMER_INDEX):
                try:
                    request(args.host, "DELETE", f"/{index}")
                except Failure:
                    pass

    print("all gates held")
    return 0


if __name__ == "__main__":
    sys.exit(main())
