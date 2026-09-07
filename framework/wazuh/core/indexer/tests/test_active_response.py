# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import jsonschema
import pytest

from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from unittest.mock import mock_open, AsyncMock, MagicMock, patch

from wazuh.core.exception import WazuhInternalError

from wazuh.core.indexer.active_response import (
    AR_SCHEMA,
    EVENT_VISIBILITY_GRACE_SECONDS,
    ActiveResponse,
    ActiveResponseFetchTask,
    ActiveResponseBookmark,
    ActiveResponseBookmarkFile,
    ActiveResponseBuilder,
    ActiveResponseHelpers,
)

GOOD_EVENT_DOC = {"event": {"index": "idx", "doc_id": "1"}}
ONE_FOUND_DOC = {"docs": [{"_index": "idx", "_id": "1", "_source": {"k": "v"}, "found": True}]}

# Everything AR_SCHEMA lets through in `event`, since it constrains `wazuh` and nothing else.
# The unhashable doc_id sits on its own index on purpose: on `idx` the good AR would refill the
# set setdefault() had already inserted, and the empty-ids query would never happen.
UNUSABLE_EVENT_DOCS = [
    {"wazuh": {"active_response": {"location": "local"}}},
    {"event": None},
    {"event": "abc"},
    {"event": 5},
    {"event": ["x"]},
    {"event": {"index": {}, "doc_id": "1"}},
    {"event": {"index": None, "doc_id": "1"}},
    {"event": {"index": "", "doc_id": "1"}},
    {"event": {"index": "idx", "doc_id": None}},
    {"event": {"index": "other-idx", "doc_id": {}}},
]


def _ar(doc_source):
    return ActiveResponse(doc_source=doc_source, bookmark=ActiveResponseBookmark())


def _stamp(seconds_ago=0):
    """An ISO8601 `@timestamp` that many seconds in the past."""
    return (datetime.now(timezone.utc) - timedelta(seconds=seconds_ago)).isoformat().replace("+00:00", "Z")


def _missing_event_doc(seconds_ago):
    """An active response whose referenced event is not in the mget result, stamped in the past."""
    return {
        "@timestamp": _stamp(seconds_ago),
        "event": {"index": "idx", "doc_id": "missing"},
    }


class TestActiveResponseBookmark:
    """Tests for ActiveResponseBookmark."""

    def test_build_sort_default_fields(self):
        bookmark = ActiveResponseBookmark()

        result = bookmark.build_sort()

        assert result == [{"@timestamp": "asc"}, {"_id": "asc"}]

    def test_build_sort_custom_fields(self):
        bookmark = ActiveResponseBookmark(sort_fields=["a", "b"])

        result = bookmark.build_sort()

        assert result == [{"a": "asc"}, {"b": "asc"}]

    @pytest.mark.parametrize(
        "sort,expected",
        [
            ([1, 2], [1, 2]),
            ([], None),
        ],
    )
    def test_to_search_after(self, sort, expected):
        bookmark = ActiveResponseBookmark(sort=sort)

        assert bookmark.to_search_after() == expected

    def test_update_overwrites_sort(self):
        bookmark = ActiveResponseBookmark(sort=[1])

        bookmark.update([2, 3])

        assert bookmark.sort == [2, 3]


class TestActiveResponseBookmarkFile:
    """Tests for ActiveResponseBookmarkFile."""

    @patch("wazuh.core.indexer.active_response.os.path.exists", return_value=False)
    def test_load_no_file(self, _):
        bf = ActiveResponseBookmarkFile(path="dummy")

        assert bf.sort == []
        assert bf.only_events_after is None

    @patch("wazuh.core.indexer.active_response.os.path.exists", return_value=True)
    @patch(
        "builtins.open",
        new_callable=mock_open,
        read_data='{"sort":[1],"sort_fields":["a"],"only_events_after":123}',
    )
    def test_load_valid_file(self, *_):
        bf = ActiveResponseBookmarkFile(path="dummy")

        assert bf.sort == [1]
        assert bf.sort_fields == ["a"]
        assert bf.only_events_after == 123

    @patch("wazuh.core.indexer.active_response.os.path.exists", return_value=True)
    @patch("builtins.open", new_callable=mock_open, read_data="invalid json")
    def test_load_invalid_json(self, *_):
        bf = ActiveResponseBookmarkFile(path="dummy")

        assert bf.sort == []
        assert bf.only_events_after is None

    @patch("builtins.open", new_callable=mock_open)
    @patch("wazuh.core.indexer.active_response.os.fsync")
    def test_save_writes_file(self, mock_fsync, mock_file):
        bf = ActiveResponseBookmarkFile(path="dummy")

        bf.sort = [1]
        bf.sort_fields = ["a"]
        bf.only_events_after = 123

        bf._save()

        handle = mock_file()
        handle.write.assert_called()
        mock_fsync.assert_called_once()

    @patch.object(ActiveResponseBookmarkFile, "_save")
    def test_ensure_only_events_after_sets_value(self, mock_save):
        bf = ActiveResponseBookmarkFile(path="dummy")

        result = bf.ensure_only_events_after()

        assert isinstance(result, int)
        mock_save.assert_called_once()

    @patch.object(ActiveResponseBookmarkFile, "_save")
    def test_ensure_only_events_after_keeps_existing(self, mock_save):
        bf = ActiveResponseBookmarkFile(path="dummy")
        bf.only_events_after = 123

        result = bf.ensure_only_events_after()

        assert result == 123
        mock_save.assert_not_called()

    @patch.object(ActiveResponseBookmarkFile, "_save")
    def test_update_triggers_save_when_changed(self, mock_save):
        bf = ActiveResponseBookmarkFile(path="dummy")

        bf.update([1])

        assert bf.sort == [1]
        mock_save.assert_called_once()

    @patch.object(ActiveResponseBookmarkFile, "_save")
    def test_update_does_not_save_if_same(self, mock_save):
        bf = ActiveResponseBookmarkFile(path="dummy")
        bf.sort = [1]

        bf.update([1])

        mock_save.assert_not_called()

    @patch.object(ActiveResponseBookmarkFile, "_save")
    @patch("wazuh.core.indexer.active_response.os.path.exists", return_value=True)
    def test_load_caps_a_future_dated_cursor(self, _, mock_save):
        """A cursor written by the code that advanced it once per delivered response can hold a
        future `@timestamp`. Left as read, search_after asks for documents sorting after an instant
        the query's own `lte: now` ceiling excludes, so every cycle reads zero hits until
        wall-clock time catches up and the only recovery is deleting the file."""
        future_ms = int(datetime.now(timezone.utc).timestamp() * 1000) + 3_600_000

        with patch("builtins.open", new_callable=mock_open, read_data=f'{{"sort":[{future_ms},"doc-1"]}}'):
            bf = ActiveResponseBookmarkFile(path="dummy")

        assert bf.sort[0] < future_ms
        assert bf.sort[1] == "doc-1"
        # Persisted, or a cycle that reads no hits writes no cursor and leaves the bad value on
        # disk for the next restart to load again.
        mock_save.assert_called_once()

    @patch.object(ActiveResponseBookmarkFile, "_save")
    @patch("wazuh.core.indexer.active_response.os.path.exists", return_value=True)
    def test_load_leaves_a_past_cursor_alone(self, _, mock_save):
        """The cap must not touch a healthy cursor: rewriting it would move the stream."""
        past_ms = int(datetime.now(timezone.utc).timestamp() * 1000) - 3_600_000

        with patch("builtins.open", new_callable=mock_open, read_data=f'{{"sort":[{past_ms},"doc-1"]}}'):
            bf = ActiveResponseBookmarkFile(path="dummy")

        assert bf.sort == [past_ms, "doc-1"]
        mock_save.assert_not_called()

    @patch.object(ActiveResponseBookmarkFile, "_save")
    @patch("wazuh.core.indexer.active_response.os.path.exists", return_value=True)
    def test_load_leaves_a_cursor_that_does_not_lead_with_a_timestamp(self, _, mock_save):
        """Nothing validates the file, so the comparison has to survive whatever is in it."""
        with patch("builtins.open", new_callable=mock_open, read_data='{"sort":["nope","doc-1"]}'):
            bf = ActiveResponseBookmarkFile(path="dummy")

        assert bf.sort == ["nope", "doc-1"]
        mock_save.assert_not_called()


class TestActiveResponse:
    """Tests for ActiveResponse.target_agents."""

    @pytest.mark.parametrize(
        "location,agent_id,available_agents,expected",
        [
            ("all", "1", ["1", "2"], ["1", "2"]),
            ("local", "1", ["1", "2"], ["1"]),
            ("local", "3", ["1", "2"], ["3"]),  # HTTPS: Create task regardless of connection status
            ("defined-agent", "2", ["1", "2"], ["2"]),
            ("defined-agent", "3", ["1", "2"], ["3"]),  # HTTPS: Create task regardless of connection status
            ("unknown", "1", ["1", "2"], []),
        ],
    )
    def test_target_agents(self, location, agent_id, available_agents, expected):
        ar = ActiveResponse(
            doc_source={
                "wazuh": {
                    "active_response": {
                        "location": location,
                        "agent_id": agent_id,
                    },
                    "agent": {
                        "id": agent_id,
                    },
                }
            },
            bookmark=ActiveResponseBookmark(),
        )

        result = ar.target_agents(available_agents)

        assert result == expected


class TestActiveResponseHelpers:
    """Tests for ActiveResponseHelpers."""

    class TestGetAllAgents:
        """Tests for get_all_agents."""

        @patch("wazuh.core.indexer.active_response.WazuhDBQueryAgents")
        def test_success(self, mock_db):
            mock_ctx = MagicMock()
            mock_ctx.run.return_value = {"items": [{"id": "1"}, {"id": "2"}]}
            mock_db.return_value.__enter__.return_value = mock_ctx

            result = ActiveResponseHelpers.get_all_agents()

            assert result == ["1", "2"]

        @patch("wazuh.core.indexer.active_response.WazuhDBQueryAgents")
        @patch("wazuh.core.indexer.active_response.ActiveResponseHelpers.logger")
        def test_error(self, mock_logger, mock_db):
            from wazuh.core.exception import WazuhError

            mock_db.side_effect = WazuhError(1)

            result = ActiveResponseHelpers.get_all_agents()

            assert result == []
            mock_logger.error.assert_called_once()

    class TestFetchActiveResponseDocs:
        """Tests for fetch_active_response_docs."""

        @pytest.mark.asyncio
        @patch("wazuh.core.indexer.active_response.get_indexer_client")
        async def test_with_search_after(self, mock_client):
            client = AsyncMock()
            client.search.return_value = {"hits": {"hits": []}}
            mock_client.return_value.__aenter__.return_value = client

            bookmark = MagicMock()
            bookmark.build_sort.return_value = [{"a": "asc"}]
            bookmark.to_search_after.return_value = [1]

            await ActiveResponseHelpers.fetch_active_response_docs(bookmark)

            body = client.search.call_args.kwargs["body"]

            assert body["search_after"] == [1]

        @pytest.mark.asyncio
        @patch("wazuh.core.indexer.active_response.get_indexer_client")
        async def test_without_search_after_uses_timestamp(self, mock_client):
            client = AsyncMock()
            client.search.return_value = {"hits": {"hits": []}}
            mock_client.return_value.__aenter__.return_value = client

            bookmark = MagicMock()
            bookmark.build_sort.return_value = []
            bookmark.to_search_after.return_value = None
            bookmark.ensure_only_events_after.return_value = 123

            await ActiveResponseHelpers.fetch_active_response_docs(bookmark)

            body = client.search.call_args.kwargs["body"]

            assert (
                body["query"]["bool"]["filter"][0]["range"]["@timestamp"]["gte"] == 123
            )
            # Bounded above as well, so a future-stamped document cannot enter the page and
            # move the cursor past everything created before it.
            assert (
                body["query"]["bool"]["filter"][0]["range"]["@timestamp"]["lte"]
                <= int(datetime.now(timezone.utc).timestamp() * 1000)
            )

        @pytest.mark.asyncio
        @patch("wazuh.core.indexer.active_response.get_indexer_client")
        async def test_search_after_is_still_bounded_above(self, mock_client):
            """The cursor branch carries no gte, so the upper bound is the only thing keeping a
            future-stamped document out of the page it would otherwise skip past."""
            client = AsyncMock()
            client.search.return_value = {"hits": {"hits": []}}
            mock_client.return_value.__aenter__.return_value = client

            bookmark = MagicMock()
            bookmark.build_sort.return_value = [{"@timestamp": "asc"}]
            bookmark.to_search_after.return_value = [1, "a"]

            await ActiveResponseHelpers.fetch_active_response_docs(bookmark)

            timestamp_range = client.search.call_args.kwargs["body"]["query"]["bool"]["filter"][0][
                "range"
            ]["@timestamp"]

            assert "gte" not in timestamp_range
            assert timestamp_range["lte"] <= int(datetime.now(timezone.utc).timestamp() * 1000)
            bookmark.ensure_only_events_after.assert_not_called()

        @pytest.mark.asyncio
        @patch("wazuh.core.indexer.active_response.get_indexer_client")
        async def test_the_page_extent_is_recorded_before_filtering(self, mock_client):
            """What the cursor follows is how far the page reached, so it is taken from the last hit
            and not from the documents that survive validation below."""
            client = AsyncMock()
            client.search.return_value = {
                "hits": {
                    "hits": [
                        {"_source": {"k": "v"}, "_id": "1", "_index": "idx", "sort": [1, "1"]},
                        {"_source": {"k": "v"}, "_id": "2", "_index": "idx", "sort": [2, "2"]},
                    ]
                }
            }
            mock_client.return_value.__aenter__.return_value = client

            # Seeded with a cursor so the read takes the search_after branch: the initial branch
            # resolves only_events_after, which only the file-backed bookmark implements.
            bookmark = ActiveResponseBookmark(sort=[0, "0"])

            await ActiveResponseHelpers.fetch_active_response_docs(bookmark)

            assert bookmark.page_end_sort == [2, "2"]

        @pytest.mark.asyncio
        @patch("wazuh.core.indexer.active_response.get_indexer_client")
        async def test_an_empty_page_leaves_the_cursor_alone(self, mock_client):
            client = AsyncMock()
            client.search.return_value = {"hits": {"hits": []}}
            mock_client.return_value.__aenter__.return_value = client

            bookmark = ActiveResponseBookmark(sort=[0, "0"])

            await ActiveResponseHelpers.fetch_active_response_docs(bookmark)

            assert bookmark.page_end_sort is None

        @pytest.mark.asyncio
        @patch("wazuh.core.indexer.active_response.get_indexer_client")
        async def test_validation_filters_invalid_docs(self, mock_client):
            client = AsyncMock()
            client.search.return_value = {
                "hits": {
                    "hits": [
                        {"_source": {"valid": True}, "_id": "1", "_index": "idx", "sort": [1, "1"]},
                        {"_source": {"invalid": True}, "_id": "2", "_index": "idx", "sort": [2, "2"]},
                    ]
                }
            }
            mock_client.return_value.__aenter__.return_value = client

            bookmark = MagicMock()
            bookmark.build_sort.return_value = []
            bookmark.to_search_after.return_value = [1]

            with patch(
                "wazuh.core.indexer.active_response.jsonschema.validate"
            ) as mock_validate:
                from jsonschema import ValidationError

                mock_validate.side_effect = [None, ValidationError("fail")]

                result = await ActiveResponseHelpers.fetch_active_response_docs(
                    bookmark, validate=True
                )

            assert len(result) == 1
            assert result[0]["_id"] == "1"

    class TestGetEventsByAr:
        """Tests for get_events_by_ar."""

        @pytest.mark.asyncio
        @patch("wazuh.core.indexer.active_response.get_indexer_client")
        async def test_groups_and_fetches_events(self, mock_client):
            client = AsyncMock()
            client.mget.return_value = {
                "docs": [
                    {
                        "_index": "idx",
                        "_id": "1",
                        "_source": {"k": "v"},
                        "found": True,
                    }
                ]
            }
            mock_client.return_value.__aenter__.return_value = client

            ar = ActiveResponse(
                doc_source={"event": {"index": "idx", "doc_id": "1"}},
                bookmark=ActiveResponseBookmark(),
            )

            result = await ActiveResponseHelpers.get_events_by_ar([ar])

            assert result == {"idx": {"1": {"k": "v"}}}

        @pytest.mark.asyncio
        @patch("wazuh.core.indexer.active_response.get_indexer_client")
        async def test_ignores_not_found(self, mock_client):
            client = AsyncMock()
            client.mget.return_value = {"docs": [{"found": False}]}
            mock_client.return_value.__aenter__.return_value = client

            ar = ActiveResponse(
                doc_source={"event": {"index": "idx", "doc_id": "1"}},
                bookmark=ActiveResponseBookmark(),
            )

            result = await ActiveResponseHelpers.get_events_by_ar([ar])

            assert result == {}

        @pytest.mark.parametrize("doc_source", UNUSABLE_EVENT_DOCS)
        @pytest.mark.asyncio
        @patch("wazuh.core.indexer.active_response.get_indexer_client")
        async def test_unusable_event_does_not_discard_the_page(self, mock_client, doc_source):
            # `event` is optional and unconstrained. Some of these raise on the lookup; the rest
            # are hashable and would reach mget as a poisoned index or id and come back a 400.
            # Either way the loop runs before any I/O, so one of them took down the whole page.
            client = AsyncMock()
            client.mget.return_value = ONE_FOUND_DOC
            mock_client.return_value.__aenter__.return_value = client

            result = await ActiveResponseHelpers.get_events_by_ar([_ar(doc_source), _ar(GOOD_EVENT_DOC)])

            assert result == {"idx": {"1": {"k": "v"}}}
            # The query actually issued: a mocked mget hides a poisoned index or an empty id list,
            # so the call itself is what has to be asserted, not just the absence of an exception.
            client.mget.assert_awaited_once_with(index="idx", body={"ids": ["1"]})

        @pytest.mark.asyncio
        @patch("wazuh.core.indexer.active_response.get_indexer_client")
        async def test_found_without_source_is_not_an_event(self, mock_client):
            """An index that does not store `_source` answers `found` with nothing to merge."""
            client = AsyncMock()
            client.mget.return_value = {"docs": [{"_index": "idx", "_id": "1", "found": True}]}
            mock_client.return_value.__aenter__.return_value = client

            result = await ActiveResponseHelpers.get_events_by_ar([_ar(GOOD_EVENT_DOC)])

            assert result == {}


class TestActiveResponseBuilder:
    """Tests for ActiveResponseBuilder."""

    class TestInit:
        """Tests for __init__."""

        def test_init(self):
            logger = MagicMock()
            bookmark = MagicMock()

            builder = ActiveResponseBuilder(
                logger=logger,
                all_agents=["1"],
                bookmark_file=bookmark,
            )

            assert builder.logger == logger
            assert builder._all_agents == ["1"]
            assert builder._ars == []
            assert builder._bookmark_file is bookmark

    class TestFetchArs:
        """Tests for fetch_ars."""

        @pytest.mark.asyncio
        @patch(
            "wazuh.core.indexer.active_response.ActiveResponseHelpers.fetch_active_response_docs"
        )
        async def test_fetch_ars(self, mock_fetch):
            mock_fetch.return_value = [
                {"_source": {"a": 1}, "sort": [1]},
            ]

            builder = ActiveResponseBuilder(
                logger=MagicMock(),
                all_agents=[],
                bookmark_file=MagicMock(),
            )

            result = await builder.fetch_ars()

            assert isinstance(result, ActiveResponseBuilder)
            assert len(builder._ars) == 1
            assert isinstance(builder._ars[0], ActiveResponse)
            assert builder._ars[0].doc_source == {"a": 1}
            assert builder._ars[0].bookmark.sort == [1]

    class TestEnrich:
        """Tests for enrich_ar_with_events_info."""

        @pytest.mark.asyncio
        @patch(
            "wazuh.core.indexer.active_response.ActiveResponseHelpers.get_events_by_ar"
        )
        async def test_enrich_success(self, mock_events):
            mock_events.return_value = {"idx": {"1": {"k": "v"}}}

            ar = ActiveResponse(
                doc_source={"event": {"index": "idx", "doc_id": "1"}},
                bookmark=ActiveResponseBookmark(),
            )

            builder = ActiveResponseBuilder(
                logger=MagicMock(),
                all_agents=[],
                bookmark_file=MagicMock(),
            )
            builder._ars = [ar]

            await builder.enrich_ar_with_events_info()

            assert builder._ars[0].event == {"k": "v"}

        @pytest.mark.asyncio
        @patch(
            "wazuh.core.indexer.active_response.ActiveResponseHelpers.get_events_by_ar"
        )
        async def test_enrich_missing_event_discard(self, mock_events):
            mock_events.return_value = {}

            logger = MagicMock()

            ar = ActiveResponse(
                doc_source={"event": {"index": "idx", "doc_id": "1"}},
                bookmark=ActiveResponseBookmark(),
            )

            builder = ActiveResponseBuilder(
                logger=logger,
                all_agents=[],
                bookmark_file=MagicMock(),
            )
            builder._ars = [ar]

            await builder.enrich_ar_with_events_info(allow_empty_event=False)

            assert builder._ars == []
            logger.warning.assert_called()

        @pytest.mark.asyncio
        @patch(
            "wazuh.core.indexer.active_response.ActiveResponseHelpers.get_events_by_ar"
        )
        async def test_enrich_missing_event_keep(self, mock_events):
            mock_events.return_value = {}

            ar = ActiveResponse(
                doc_source={"event": {"index": "idx", "doc_id": "1"}},
                bookmark=ActiveResponseBookmark(),
            )

            builder = ActiveResponseBuilder(
                logger=MagicMock(),
                all_agents=[],
                bookmark_file=MagicMock(),
            )
            builder._ars = [ar]

            await builder.enrich_ar_with_events_info(allow_empty_event=True)

            assert builder._ars == [ar]
            assert builder._ars[0].event is None

        @pytest.mark.parametrize("doc_source", UNUSABLE_EVENT_DOCS)
        @pytest.mark.asyncio
        @patch("wazuh.core.indexer.active_response.ActiveResponseHelpers.get_events_by_ar")
        async def test_enrich_unusable_event_is_discarded(self, mock_events, doc_source):
            # Reachable only once get_events_by_ar() stops raising: the handler's log line reads
            # both names, and a truthy non-mapping reached .get() on a str/int/list outside the try.
            #
            # Stamped now on purpose. An unusable reference is terminal at any age, so it must not
            # take the event-visibility hold: get_events_by_ar() already refused to look it up, and
            # a reference it would not query can never become visible. Without the `usable` check
            # this document holds the whole page for the length of the grace window.
            mock_events.return_value = {"idx": {"1": {"k": "v"}}}

            logger = MagicMock()
            good = _ar(GOOD_EVENT_DOC)

            bookmark_file = ActiveResponseBookmark(page_end_sort=[9, "z"])
            builder = ActiveResponseBuilder(
                logger=logger,
                all_agents=[],
                bookmark_file=bookmark_file,
            )
            builder._ars = [_ar({**doc_source, "@timestamp": _stamp()}), good]

            await builder.enrich_ar_with_events_info(allow_empty_event=False)

            assert builder._ars == [good]
            assert builder._ars[0].event == {"k": "v"}
            assert bookmark_file.page_end_sort == [9, "z"], "a terminal discard must not hold the page"

        @pytest.mark.asyncio
        @patch("wazuh.core.indexer.active_response.ActiveResponseHelpers.get_events_by_ar")
        async def test_an_event_not_visible_yet_holds_the_page(self, mock_events):
            # The page carried two responses and only the first resolved. The cursor has to stop
            # between them, so the second is read again once its event is visible.
            mock_events.return_value = {"idx": {"1": {"k": "v"}}}

            good = ActiveResponse(
                doc_source=GOOD_EVENT_DOC, bookmark=ActiveResponseBookmark([1, "1"])
            )
            pending = ActiveResponse(
                doc_source=_missing_event_doc(5), bookmark=ActiveResponseBookmark([2, "2"])
            )

            bookmark_file = ActiveResponseBookmark(page_end_sort=[2, "2"])
            builder = ActiveResponseBuilder(
                logger=MagicMock(), all_agents=[], bookmark_file=bookmark_file
            )
            builder._ars = [good, pending]

            await builder.enrich_ar_with_events_info()

            assert builder._ars == [good]
            assert bookmark_file.page_end_sort == [1, "1"]

        @pytest.mark.asyncio
        @patch("wazuh.core.indexer.active_response.ActiveResponseHelpers.get_events_by_ar")
        async def test_holding_on_the_first_response_leaves_the_cursor_alone(self, mock_events):
            mock_events.return_value = {}

            pending = ActiveResponse(
                doc_source=_missing_event_doc(5), bookmark=ActiveResponseBookmark([1, "1"])
            )

            bookmark_file = ActiveResponseBookmark(page_end_sort=[1, "1"])
            builder = ActiveResponseBuilder(
                logger=MagicMock(), all_agents=[], bookmark_file=bookmark_file
            )
            builder._ars = [pending]

            await builder.enrich_ar_with_events_info()

            assert builder._ars == []
            assert bookmark_file.page_end_sort is None

        @pytest.mark.asyncio
        @patch("wazuh.core.indexer.active_response.ActiveResponseHelpers.get_events_by_ar")
        async def test_an_event_missing_past_the_grace_window_is_discarded(self, mock_events):
            # The counterpart of the hold: an event that never appears cannot keep the cursor,
            # or one broken reference would stop delivery for the whole fleet.
            mock_events.return_value = {}
            logger = MagicMock()

            stale = ActiveResponse(
                doc_source=_missing_event_doc(EVENT_VISIBILITY_GRACE_SECONDS + 60),
                bookmark=ActiveResponseBookmark([1, "1"]),
            )

            bookmark_file = ActiveResponseBookmark(page_end_sort=[1, "1"])
            builder = ActiveResponseBuilder(
                logger=logger, all_agents=[], bookmark_file=bookmark_file
            )
            builder._ars = [stale]

            await builder.enrich_ar_with_events_info()

            assert builder._ars == []
            assert bookmark_file.page_end_sort == [1, "1"]
            logger.warning.assert_called_once()

    class TestDispatch:
        """Tests for dispatch."""

        @staticmethod
        def _patched_client(mock_client, response=None, side_effect=None):
            """Wire a patched TaskManagerHTTPClient and return the client the code will use.

            dispatch() opens the client once for the whole pass and uses it as a context manager,
            so the mock has to answer __enter__ rather than being the client itself.
            """
            client = MagicMock()
            if side_effect is not None:
                client.create_task.side_effect = side_effect
            else:
                client.create_task.return_value = response or {"task_id": "task-123"}

            mock_client.return_value.__enter__.return_value = client
            return client

        @patch("wazuh.core.indexer.active_response.TaskManagerHTTPClient")
        def test_dispatch_success(self, mock_client):
            """Test successful task creation via the Task Manager."""
            client = self._patched_client(mock_client)

            # Create AR with proper structure
            ar = ActiveResponse(
                doc_source={
                    "@timestamp": "2024-01-01T00:00:00Z",
                    "wazuh": {
                        "active_response": {
                            "location": "defined-agent",
                            "agent_id": "001",
                            "name": "test-ar",
                            "executable": "test.sh",
                            "extra_arguments": None,
                            "type": "stateless",
                        }
                    },
                },
                doc_id="ar-doc-123",
                bookmark=ActiveResponseBookmark([1, "ar-doc-123"])
            )

            bookmark_file = MagicMock()
            # The page's extent is what the cursor follows now, not each response's own
            # sort: these tests drive dispatch() with _ars set directly, so it is set here.
            bookmark_file.page_end_sort = [1, "ar-doc-123"]

            builder = ActiveResponseBuilder(
                logger=MagicMock(),
                all_agents=["001"],
                bookmark_file=bookmark_file,
            )
            builder._ars = [ar]

            result = builder.dispatch()

            assert result is builder

            # Verify the task was created with the right fields
            client.create_task.assert_called_once()
            sent = client.create_task.call_args.kwargs
            assert sent["task_type"] == "active_response"
            assert sent["agent_id"] == "001"
            # The AR document id, mixed into the deterministic task id so the same alert produces
            # the same task on any cluster node.
            assert sent["source_id"] == "ar-doc-123"
            assert sent["create_time"] == 1704067200  # 2024-01-01T00:00:00Z
            assert "payload" in sent

            # Verify bookmark was updated
            bookmark_file.update.assert_called_once_with([1, "ar-doc-123"])

        def test_dispatch_no_ars(self):
            """Test dispatch with no active responses."""
            builder = ActiveResponseBuilder(
                logger=MagicMock(),
                all_agents=["1"],
                bookmark_file=MagicMock(),
            )
            builder._ars = []

            result = builder.dispatch()

            assert result is builder

        @patch("wazuh.core.indexer.active_response.TaskManagerHTTPClient")
        def test_dispatch_holds_the_page_when_task_manager_is_unreachable(self, mock_client):
            """A Task Manager that cannot be reached says nothing about this response, so the page
            must be HELD rather than cleared: clearing it would drop every response on it over a
            transient outage, turning at-least-once delivery into at-most-once."""
            from wazuh.core.exception import WazuhInternalError

            # 2021 is "cannot connect": the module is not listening. A WazuhInternalError is a
            # sibling of WazuhError under WazuhException rather than a subclass, so catching only
            # WazuhError would let it escape the loop and abort the cycle from here on.
            self._patched_client(mock_client, side_effect=WazuhInternalError(2021))

            ar = ActiveResponse(
                doc_source={
                    "@timestamp": "2024-01-01T00:00:00Z",
                    "wazuh": {
                        "active_response": {
                            "location": "defined-agent",
                            "agent_id": "001",
                            "name": "test-ar",
                            "executable": "test.sh",
                            "extra_arguments": None,
                            "type": "stateless",
                        }
                    },
                },
                doc_id="ar-doc-123",
                bookmark=ActiveResponseBookmark([1])
            )

            logger = MagicMock()
            bookmark_file = MagicMock()
            # The page's extent is what the cursor follows now, not each response's own
            # sort: these tests drive dispatch() with _ars set directly, so it is set here.
            bookmark_file.page_end_sort = [1]

            builder = ActiveResponseBuilder(
                logger=logger,
                all_agents=["001"],
                bookmark_file=bookmark_file,
            )
            builder._ars = [ar]

            builder.dispatch()

            logger.error.assert_called_once()
            bookmark_file.update.assert_not_called()

        def test_dispatch_advances_the_cursor_on_a_page_that_dispatched_nothing(self):
            """Every document of the page was discarded before dispatch (invalid schema, unusable
            event reference, unparseable @timestamp), so nothing reaches _ars. The cursor still has
            to clear the page, or it is re-read every polling cycle for as long as the document
            exists."""
            bookmark_file = MagicMock()
            bookmark_file.page_end_sort = [9, "z"]

            builder = ActiveResponseBuilder(
                logger=MagicMock(), all_agents=[], bookmark_file=bookmark_file
            )
            builder._ars = []

            builder.dispatch()

            bookmark_file.update.assert_called_once_with([9, "z"])

        @patch("wazuh.core.indexer.active_response.TaskManagerHTTPClient")
        def test_dispatch_follows_the_page_not_the_last_dispatched_response(self, mock_client):
            """The cursor clears the whole page, including documents that came after the last one
            dispatched. Following the last dispatched response instead would leave them to be
            re-read."""
            self._patched_client(mock_client, response={"task_id": "t1"})

            ar = ActiveResponse(
                doc_source={
                    "@timestamp": "2024-01-01T00:00:00Z",
                    "wazuh": {
                        "active_response": {
                            "location": "defined-agent",
                            "agent_id": "001",
                            "name": "test-ar",
                            "executable": "test.sh",
                            "extra_arguments": None,
                            "type": "stateless",
                        }
                    },
                },
                doc_id="ar-doc-123",
                bookmark=ActiveResponseBookmark([1, "ar-doc-123"]),
            )

            bookmark_file = MagicMock()
            bookmark_file.page_end_sort = [7, "later-doc"]

            builder = ActiveResponseBuilder(
                logger=MagicMock(), all_agents=["001"], bookmark_file=bookmark_file
            )
            builder._ars = [ar, ar]

            builder.dispatch()

            # Once for the page, not once per response, which also means one fsync per cycle.
            bookmark_file.update.assert_called_once_with([7, "later-doc"])

        @patch("wazuh.core.indexer.active_response.TaskManagerHTTPClient")
        def test_dispatch_clears_the_page_when_task_manager_refuses(self, mock_client):
            """A refusal is a decision ABOUT THIS TASK, not a transport failure, so the page still
            clears -- the contrast with the hold case above.

            It reaches the handler differently now: the framed socket returned a refusal in the
            body (`status != "ok"`) and never raised, while TaskManagerHTTPClient raises WazuhError
            2019 on any non-2xx. dispatch() therefore has to tell that one code apart from every
            transport failure, or a permanently invalid document would freeze the cursor on its
            page for as long as it existed.
            """
            from wazuh.core.exception import WazuhError

            self._patched_client(
                mock_client,
                side_effect=WazuhError(2019, extra_message="invalid_agent"),
            )

            ar = ActiveResponse(
                doc_source={
                    "@timestamp": "2024-01-01T00:00:00Z",
                    "wazuh": {
                        "active_response": {
                            "location": "defined-agent",
                            "agent_id": "001",
                            "name": "test-ar",
                            "executable": "test.sh",
                            "extra_arguments": None,
                            "type": "stateless",
                        }
                    },
                },
                doc_id="ar-doc-123",
                bookmark=ActiveResponseBookmark([1])
            )

            logger = MagicMock()
            bookmark_file = MagicMock()
            # The page's extent is what the cursor follows now, not each response's own
            # sort: these tests drive dispatch() with _ars set directly, so it is set here.
            bookmark_file.page_end_sort = [1]

            builder = ActiveResponseBuilder(
                logger=logger,
                all_agents=["001"],
                bookmark_file=bookmark_file,
            )
            builder._ars = [ar]

            builder.dispatch()

            # Error should be logged, carrying the reason the Task Manager gave
            logger.error.assert_called_once()
            assert "invalid_agent" in str(logger.error.call_args)
            # Bookmark should still be updated
            bookmark_file.update.assert_called_once_with([1])

        @patch("wazuh.core.indexer.active_response.TaskManagerHTTPClient")
        def test_dispatch_missing_timestamp(self, mock_client):
            """Test dispatch skips ARs without @timestamp."""
            client = self._patched_client(mock_client)

            ar = ActiveResponse(
                doc_source={
                    # Missing @timestamp
                    "wazuh": {
                        "active_response": {
                            "location": "defined-agent",
                            "agent_id": "001",
                            "name": "test-ar",
                            "executable": "test.sh",
                            "extra_arguments": None,
                            "type": "stateless",
                        }
                    },
                },
                doc_id="ar-doc-123",
                bookmark=ActiveResponseBookmark([1])
            )

            logger = MagicMock()

            builder = ActiveResponseBuilder(
                logger=logger,
                all_agents=["001"],
                bookmark_file=MagicMock(),
            )
            builder._ars = [ar]

            builder.dispatch()

            # Should log warning and skip
            logger.warning.assert_called_once()
            assert "missing @timestamp" in str(logger.warning.call_args)
            # No task should be created. The client itself IS built -- it is opened once for the
            # whole pass, before any AR is examined -- so this asserts on the request, not the
            # connection.
            client.create_task.assert_not_called()

        @patch("wazuh.core.indexer.active_response.TaskManagerHTTPClient")
        def test_dispatch_with_event_enrichment(self, mock_client):
            """Test dispatch includes enriched event data in payload."""
            client = self._patched_client(mock_client)

            ar = ActiveResponse(
                doc_source={
                    "@timestamp": "2024-01-01T00:00:00Z",
                    "wazuh": {
                        "active_response": {
                            "location": "defined-agent",
                            "agent_id": "001",
                            "name": "test-ar",
                            "executable": "test.sh",
                            "extra_arguments": None,
                            "type": "stateless",
                        }
                    },
                    "ar_field": "ar_value",
                },
                doc_id="ar-doc-123",
                bookmark=ActiveResponseBookmark([1]),
                event={
                    "wazuh": {"rule": {"id": "100002"}},
                    "event_field": "event_value"
                }
            )

            builder = ActiveResponseBuilder(
                logger=MagicMock(),
                all_agents=["001"],
                bookmark_file=MagicMock(),
            )
            builder._ars = [ar]

            builder.dispatch()

            # Verify payload includes both AR and event data
            payload = client.create_task.call_args.kwargs["payload"]

            # AR data should be present
            assert payload["ar_field"] == "ar_value"
            # Event data should be merged
            assert payload["event_field"] == "event_value"
            # Wazuh sections should be merged
            assert payload["wazuh"]["active_response"]["name"] == "test-ar"
            assert payload["wazuh"]["rule"]["id"] == "100002"


class TestActiveResponseFetchTask:
    """Tests for ActiveResponseFetchTask."""

    class TestInit:
        """Tests for __init__."""

        def test_with_custom_interval(self):
            server = MagicMock()
            server.cluster_items = {
                "intervals": {"common": {"active_response_polling": 10}}
            }

            task = ActiveResponseFetchTask(server)

            assert task.polling_interval == 10

        def test_with_default_interval(self):
            server = MagicMock()
            server.cluster_items = {}

            task = ActiveResponseFetchTask(server)

            assert task.polling_interval == task.DEFAULT_POLLING_INTERVAL

    class TestActiveResponseProcessing:
        """Tests for active_response_processing."""

        @pytest.mark.asyncio
        @patch("wazuh.core.indexer.active_response.ActiveResponseBuilder")
        async def test_success_flow(self, mock_builder_cls):
            mock_builder = MagicMock()
            mock_builder.fetch_ars = AsyncMock()
            mock_builder.enrich_ar_with_events_info = AsyncMock()

            mock_builder_cls.return_value = mock_builder

            server = MagicMock()
            server.cluster_items = {}

            task = ActiveResponseFetchTask(server)

            await task.active_response_processing()

            mock_builder.fetch_ars.assert_awaited_once_with(validate=True)
            mock_builder.enrich_ar_with_events_info.assert_awaited_once()
            mock_builder.dispatch.assert_called_once()

        @pytest.mark.asyncio
        @patch("wazuh.core.indexer.active_response.ActiveResponseBuilder")
        async def test_handles_exception(self, mock_builder_cls):
            from wazuh.core.exception import IndexerUnavailableError

            mock_builder = MagicMock()
            mock_builder.fetch_ars = AsyncMock(side_effect=IndexerUnavailableError(2200))

            mock_builder_cls.return_value = mock_builder

            server = MagicMock()
            server.cluster_items = {}

            task = ActiveResponseFetchTask(server)
            task.logger = MagicMock()

            await task.active_response_processing()

            task.logger.warning.assert_called_once_with("Cannot connect to Wazuh Indexer")

    class TestRun:
        """Tests for run."""

        @pytest.mark.asyncio
        @patch(
            "wazuh.core.indexer.active_response.asyncio.sleep", new_callable=AsyncMock
        )
        async def test_single_iteration(self, mock_sleep):
            server = MagicMock()
            server.cluster_items = {
                "intervals": {"common": {"active_response_polling": 1}}
            }

            task = ActiveResponseFetchTask(server)

            task.active_response_processing = AsyncMock()

            # cortar el loop después de 1 iteración
            async def stop_loop(*args, **kwargs):
                raise asyncio.CancelledError()

            import asyncio

            mock_sleep.side_effect = stop_loop

            with pytest.raises(asyncio.CancelledError):
                await task.run()

            task.active_response_processing.assert_awaited_once()
            mock_sleep.assert_awaited_once_with(1)

        @pytest.mark.asyncio
        @patch(
            "wazuh.core.indexer.active_response.asyncio.sleep", new_callable=AsyncMock
        )
        async def test_handles_processing_error(self, mock_sleep):
            import asyncio

            server = MagicMock()
            server.cluster_items = {
                "intervals": {"common": {"active_response_polling": 1}}
            }

            task = ActiveResponseFetchTask(server)
            task.logger = MagicMock()

            task.active_response_processing = AsyncMock(side_effect=Exception("boom"))

            async def stop_loop(*args, **kwargs):
                raise asyncio.CancelledError()

            mock_sleep.side_effect = stop_loop

            with pytest.raises(asyncio.CancelledError):
                await task.run()

            task.logger.error.assert_called_once()


#: A `found` mget hit that carries no `_source`: an index that does not store it.
NO_SOURCE = object()

ALERT_REF = {"index": "wazuh-alerts", "doc_id": "alert-1"}


def _channel(location, agent_id=None):
    """The `wazuh.active_response` block the producer writes for a channel."""
    return {
        "agent_id": agent_id,
        "executable": "block-ip",
        "extra_arguments": "1.2.3.4",
        "location": location,
        "name": "test-ar",
        "type": "stateless",
    }


GOOD_AR = {
    "event": ALERT_REF,
    "wazuh": {"agent": {"id": "001"}, "active_response": _channel("defined-agent", "007")},
}

# A referenced document's shape is out of AR_SCHEMA's reach: it is only known after the mget.
EVENT_WAZUH_IS_A_STRING = {
    "event": {"index": "other-idx", "doc_id": "weird-1"},
    "wazuh": {"active_response": _channel("defined-agent", "007")},
}

# V1 and V2 fail AR_SCHEMA; V3 and V5 pass it and used to raise out of dispatch() or
# get_events_by_ar(); the last two fail it outright. Adding a shape is one line here.
POISON_DOCS = [
    pytest.param(
        {"event": ALERT_REF, "wazuh": {"active_response": _channel("local")}},
        id="local-without-wazuh-agent",
    ),
    pytest.param(
        {"event": ALERT_REF, "wazuh": {"agent": {"name": "x"}, "active_response": _channel("local")}},
        id="local-agent-without-id",
    ),
    pytest.param(EVENT_WAZUH_IS_A_STRING, id="event-wazuh-is-a-string"),
    pytest.param(
        {
            "event": {"index": "nosource-idx", "doc_id": "x"},
            "wazuh": {"active_response": _channel("defined-agent", "007")},
        },
        id="event-found-without-source",
    ),
    pytest.param({}, id="empty"),
    pytest.param({"wazuh": "x"}, id="wazuh-is-a-string"),
]

EVENTS = {
    "wazuh-alerts": {"alert-1": {"wazuh": {"agent": {"id": "001"}}, "rule": {"id": "5710"}}},
    "other-idx": {"weird-1": {"wazuh": "not-an-object"}},
    "nosource-idx": {"x": NO_SOURCE},
}


def _hit(doc_id, source, sort, seconds_ago=300):
    """A search hit for an AR document, stamped past the grace window so a missing event is
    discarded rather than held: a hold would also keep the cursor still, for another reason."""
    return {
        "_id": doc_id,
        "_index": ".ds-wazuh-active-responses-000001",
        "_source": {"@timestamp": _stamp(seconds_ago), **source},
        "sort": sort,
    }


class _FakeIndexer:
    """search() answers with the page as given; mget() serves `events` as {index: {doc_id: source}}."""

    def __init__(self, hits, events):
        self.hits = hits
        self.events = events

    async def search(self, index, body):
        return {"hits": {"hits": self.hits}}

    async def mget(self, index, body):
        docs = []
        for doc_id in body["ids"]:
            source = self.events.get(index, {}).get(doc_id)
            doc = {"_index": index, "_id": doc_id, "found": source is not None}
            if source is not None and source is not NO_SOURCE:
                doc["_source"] = source
            docs.append(doc)
        return {"docs": docs}


class _FakeTaskManager:
    """Records create_task() calls as (source_id, agent_id), or raises `fail` when set."""

    def __init__(self, fail=None):
        self.created = []
        self.fail = fail

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def create_task(self, agent_id, task_type, create_time, payload, source_id):
        if self.fail:
            raise self.fail
        self.created.append((source_id, agent_id))
        return {"task_id": f"t{len(self.created)}"}


class _SpyBookmark(ActiveResponseBookmark):
    """A real bookmark that records the cursor writes instead of persisting them."""

    def __init__(self):
        super().__init__()
        self.updates = []

    def ensure_only_events_after(self):
        return 0

    def update(self, sort):
        self.updates.append(sort)
        super().update(sort)


async def _run_cycle(hits, events=EVENTS, task_manager=None, all_agents=("001", "007")):
    """One active_response_processing() over a fake indexer and Task Manager.

    Returns the Task Manager, the bookmark and the logger the cycle used."""
    task_manager = task_manager if task_manager is not None else _FakeTaskManager()
    bookmark = _SpyBookmark()
    indexer = _FakeIndexer(hits, events)

    @asynccontextmanager
    async def indexer_client():
        yield indexer

    logger = MagicMock()
    server = MagicMock()
    server.logger.getChild.return_value = logger
    server.cluster_items = {}

    with (
        patch("wazuh.core.indexer.active_response.get_indexer_client", indexer_client),
        patch("wazuh.core.indexer.active_response.TaskManagerHTTPClient", lambda: task_manager),
        patch("wazuh.core.indexer.active_response.ActiveResponseBookmarkFile", lambda: bookmark),
        patch(
            "wazuh.core.indexer.active_response.ActiveResponseHelpers.get_all_agents",
            return_value=list(all_agents),
        ),
    ):
        await ActiveResponseFetchTask(server).active_response_processing()

    return task_manager, bookmark, logger


class TestCycleSurvivesAnyDocument:
    """No document the indexer accepts into the stream may abort a polling cycle: the rest of the
    page is still dispatched and the cursor moves past all of it."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("poison", POISON_DOCS)
    async def test_cycle_survives_arbitrary_document(self, poison):
        hits = [_hit("poison", poison, sort=[1, "poison"]), _hit("good", GOOD_AR, sort=[2, "good"])]

        task_manager, bookmark, _ = await _run_cycle(hits)

        assert task_manager.created == [("good", "007")]
        assert bookmark.updates == [[2, "good"]]

    @pytest.mark.asyncio
    async def test_unusable_shape_is_logged_with_its_id(self):
        hits = [_hit("poison", EVENT_WAZUH_IS_A_STRING, sort=[1, "poison"])]

        _, _, logger = await _run_cycle(hits)

        warnings = [str(call.args[0]) for call in logger.warning.call_args_list]
        assert any("`poison`" in message and "TypeError" in message for message in warnings)

    @pytest.mark.asyncio
    async def test_transport_failure_still_holds_the_page_when_a_shape_error_also_occurred(self):
        hits = [
            _hit("poison", EVENT_WAZUH_IS_A_STRING, sort=[1, "poison"]),
            _hit("good", GOOD_AR, sort=[2, "good"]),
        ]

        _, bookmark, _ = await _run_cycle(
            hits, task_manager=_FakeTaskManager(fail=WazuhInternalError(2021))
        )

        assert bookmark.updates == []

    @pytest.mark.asyncio
    async def test_invalid_document_is_discarded_with_its_id_and_the_page_advances(self):
        """`defined-agent` with a null `agent_id` dispatched to nobody and said nothing; now it dies
        at validation, named, and the page still clears."""
        poison = {"event": ALERT_REF, "wazuh": {"active_response": _channel("defined-agent", None)}}
        hits = [_hit("poison", poison, sort=[1, "poison"]), _hit("good", GOOD_AR, sort=[2, "good"])]

        task_manager, bookmark, logger = await _run_cycle(hits)

        warnings = [str(call.args[0]) for call in logger.warning.call_args_list]
        assert any("`poison`" in message and "Reason:" in message for message in warnings)
        assert task_manager.created == [("good", "007")]
        assert bookmark.updates == [[2, "good"]]


# (document, substring the rejection must mention; None means accepted)
SCHEMA_TABLE = [
    pytest.param(
        {"event": ALERT_REF, "wazuh": {"agent": {"id": "001"}, "active_response": _channel("local")}},
        None,
        id="producer-local",
    ),
    pytest.param(
        {"event": ALERT_REF, "wazuh": {"active_response": _channel("defined-agent", "001")}},
        None,
        id="defined-agent",
    ),
    pytest.param(
        {"event": ALERT_REF, "wazuh": {"active_response": _channel("all")}},
        None,
        id="all-without-agent-and-null-agent-id",
    ),
    pytest.param(
        {"wazuh": {"active_response": _channel("defined-agent", "001")}},
        "event",
        id="38904-no-event",
    ),
    pytest.param(
        {"event": ALERT_REF, "wazuh": {"active_response": _channel("local")}},
        "agent",
        id="local-without-wazuh-agent",
    ),
    pytest.param(
        {"event": ALERT_REF, "wazuh": {"agent": {"name": "x"}, "active_response": _channel("local")}},
        "id",
        id="local-agent-without-id",
    ),
    pytest.param(
        {"event": ALERT_REF, "wazuh": {"agent": {"id": ""}, "active_response": _channel("local")}},
        "",
        id="local-empty-agent-id",
    ),
    pytest.param(
        {"event": ALERT_REF, "wazuh": {"active_response": _channel("defined-agent", None)}},
        "",
        id="defined-agent-null-agent-id",
    ),
    pytest.param(
        {
            "event": {"index": "wazuh-alerts", "doc_id": ""},
            "wazuh": {"active_response": _channel("defined-agent", "001")},
        },
        "",
        id="empty-doc-id",
    ),
]


class TestArSchema:
    """The schema is data, so it is tested as a table."""

    @pytest.mark.parametrize("document,rejected_with", SCHEMA_TABLE)
    def test_accepts_and_rejects(self, document, rejected_with):
        if rejected_with is None:
            jsonschema.validate(instance=document, schema=AR_SCHEMA)
            return

        with pytest.raises(jsonschema.ValidationError) as excinfo:
            jsonschema.validate(instance=document, schema=AR_SCHEMA)

        assert rejected_with in excinfo.value.message
