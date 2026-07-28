#!/usr/bin/env python3

import unittest

from result_summary import aggregate_opensearch


def stats(search: int, indexed: int, docs: int) -> dict:
    counters = {
        "search": {
            "query_total": search,
            "query_time_in_millis": search * 2,
            "fetch_total": search,
            "fetch_time_in_millis": search,
        },
        "indexing": {
            "index_total": indexed,
            "index_time_in_millis": indexed * 3,
            "index_failed": 0,
            "noop_update_total": 0,
            "delete_total": 0,
            "delete_time_in_millis": 0,
        },
    }
    return {
        "_all": {
            "total": counters,
            "primaries": {
                "docs": {"count": docs},
                "store": {"size_in_bytes": docs * 100},
                "translog": {"operations": docs},
            },
        }
    }


class AggregateOpenSearchTest(unittest.TestCase):
    def test_computes_counter_deltas_and_final_gauges(self) -> None:
        result = aggregate_opensearch(stats(10, 20, 20), stats(25, 50, 50))

        self.assertEqual(result["search_query_total"], 15)
        self.assertEqual(result["search_query_time_ms"], 30)
        self.assertEqual(result["index_total"], 30)
        self.assertEqual(result["index_time_ms"], 90)
        self.assertEqual(result["docs_final"], 50)
        self.assertEqual(result["store_bytes_final"], 5000)
        self.assertFalse(result["counter_reset_detected"])

    def test_uses_after_value_when_index_counters_reset(self) -> None:
        result = aggregate_opensearch(stats(100, 200, 200), stats(5, 10, 10))

        self.assertEqual(result["search_query_total"], 5)
        self.assertEqual(result["index_total"], 10)
        self.assertTrue(result["counter_reset_detected"])


if __name__ == "__main__":
    unittest.main()
