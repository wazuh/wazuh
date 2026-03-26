# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import pytest

from unittest.mock import mock_open, AsyncMock, MagicMock, patch

from wazuh.core.indexer.active_response import (
    ActiveResponse,
    ActiveResponseFetchTask,
    ActiveResponseBookmark,
    ActiveResponseBookmarkFile,
    ActiveResponseBuilder,
    ActiveResponseHelpers,
)


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


class TestActiveResponse:
    """Tests for ActiveResponse.target_agents."""

    @pytest.mark.parametrize(
        "location,agent_id,available_agents,expected",
        [
            ("all", "1", ["1", "2"], ["1", "2"]),
            ("local", "1", ["1", "2"], ["1"]),
            ("local", "3", ["1", "2"], []),
            ("defined-agent", "2", ["1", "2"], ["2"]),
            ("defined-agent", "3", ["1", "2"], []),
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

    class TestGetActiveAgents:
        """Tests for get_active_agents."""

        @patch("wazuh.core.indexer.active_response.WazuhDBQueryAgents")
        def test_success(self, mock_db):
            mock_ctx = MagicMock()
            mock_ctx.run.return_value = {"items": [{"id": "1"}, {"id": "2"}]}
            mock_db.return_value.__enter__.return_value = mock_ctx

            result = ActiveResponseHelpers.get_active_agents()

            assert result == ["1", "2"]

        @patch("wazuh.core.indexer.active_response.WazuhDBQueryAgents")
        @patch("wazuh.core.indexer.active_response.ActiveResponseHelpers.logger")
        def test_error(self, mock_logger, mock_db):
            from wazuh.core.exception import WazuhError

            mock_db.side_effect = WazuhError(1)

            result = ActiveResponseHelpers.get_active_agents()

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

        @pytest.mark.asyncio
        @patch("wazuh.core.indexer.active_response.get_indexer_client")
        async def test_validation_filters_invalid_docs(self, mock_client):
            client = AsyncMock()
            client.search.return_value = {
                "hits": {
                    "hits": [
                        {"_source": {"valid": True}, "_id": "1", "_index": "idx"},
                        {"_source": {"invalid": True}, "_id": "2", "_index": "idx"},
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

    class TestBuildArMessages:
        """Tests for build_ar_messages."""

        def test_with_event(self):
            ar = ActiveResponse(
                doc_source={"wazuh": {"a": 1}, "x": 1},
                bookmark=ActiveResponseBookmark(),
                event={"wazuh": {"b": 2}, "y": 2},
            )

            ar.target_agents = lambda _: ["1"]

            result = ActiveResponseHelpers.build_ar_messages([ar], ["1"])

            agent, msg, _ = result[0]

            assert agent == "1"
            assert msg["x"] == 1
            assert msg["y"] == 2
            assert msg["wazuh"]["a"] == 1
            assert msg["wazuh"]["b"] == 2

        def test_without_event(self):
            ar = ActiveResponse(
                doc_source={"wazuh": {"a": 1}},
                bookmark=ActiveResponseBookmark(),
            )

            ar.target_agents = lambda _: ["1"]

            result = ActiveResponseHelpers.build_ar_messages([ar], ["1"])

            assert result[0][1]["wazuh"]["a"] == 1

        def test_no_targets(self):
            ar = ActiveResponse(
                doc_source={"wazuh": {}},
                bookmark=ActiveResponseBookmark(),
            )

            ar.target_agents = lambda _: []

            result = ActiveResponseHelpers.build_ar_messages([ar], ["1"])

            assert result == []

    class TestIsValidAgent:
        """Tests for is_valid_agent."""

        @pytest.mark.parametrize(
            "targets,expected",
            [
                (["1"], True),
                ([], False),
            ],
        )
        def test_is_valid_agent(self, targets, expected):
            ar = MagicMock()
            ar.target_agents.return_value = targets

            result = ActiveResponseHelpers.is_valid_agent(ar, ["1"])

            assert result is expected


class TestActiveResponseBuilder:
    """Tests for ActiveResponseBuilder."""

    class TestInit:
        """Tests for __init__."""

        def test_init(self):
            logger = MagicMock()
            bookmark = MagicMock()

            builder = ActiveResponseBuilder(
                logger=logger,
                active_agents=["1"],
                bookmark_file=bookmark,
            )

            assert builder.logger == logger
            assert builder._active_agents == ["1"]
            assert builder._ars == []
            assert builder._bookmark_file is bookmark

    class TestGetTargetAgents:
        """Tests for get_target_agents."""

        def test_returns_active_agents(self):
            builder = ActiveResponseBuilder(
                logger=MagicMock(),
                active_agents=["1", "2"],
                bookmark_file=MagicMock(),
            )

            assert builder.get_target_agents() == ["1", "2"]

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
                active_agents=[],
                bookmark_file=MagicMock(),
            )

            result = await builder.fetch_ars()

            assert isinstance(result, ActiveResponseBuilder)
            assert len(builder._ars) == 1
            assert isinstance(builder._ars[0], ActiveResponse)
            assert builder._ars[0].doc_source == {"a": 1}
            assert builder._ars[0].bookmark.sort == [1]

    class TestFilter:
        """Tests for filter."""

        def test_filter(self):
            builder = ActiveResponseBuilder(
                logger=MagicMock(),
                active_agents=[],
                bookmark_file=MagicMock(),
            )

            ar1 = MagicMock()
            ar2 = MagicMock()

            builder._ars = [ar1, ar2]

            result = builder.filter(lambda ar: ar is ar1)

            assert result is builder
            assert builder._ars == [ar1]

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
                active_agents=[],
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
                active_agents=[],
                bookmark_file=MagicMock(),
            )
            builder._ars = [ar]

            await builder.enrich_ar_with_events_info(allow_empty_event=False)

            assert builder._ars == []
            logger.debug.assert_called()

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
                active_agents=[],
                bookmark_file=MagicMock(),
            )
            builder._ars = [ar]

            await builder.enrich_ar_with_events_info(allow_empty_event=True)

            assert builder._ars == [ar]
            assert builder._ars[0].event is None

    class TestKeepOnlyActiveAgents:
        """Tests for keep_only_active_agents_ars."""

        @patch(
            "wazuh.core.indexer.active_response.ActiveResponseHelpers.is_valid_agent"
        )
        def test_filters_valid_agents(self, mock_valid):
            mock_valid.side_effect = [True, False]

            builder = ActiveResponseBuilder(
                logger=MagicMock(),
                active_agents=["1"],
                bookmark_file=MagicMock(),
            )

            ar1 = MagicMock()
            ar1.bookmark.sort = [1]
            ar2 = MagicMock()
            ar2.bookmark.sort = [2]

            builder._ars = [ar1, ar2]

            builder.keep_only_active_agents_ars()

            assert builder._ars == [ar1]

        @patch(
            "wazuh.core.indexer.active_response.ActiveResponseHelpers.is_valid_agent",
            return_value=False,
        )
        def test_updates_bookmark_if_empty(self, mock_valid):
            bookmark = MagicMock()

            builder = ActiveResponseBuilder(
                logger=MagicMock(),
                active_agents=["1"],
                bookmark_file=bookmark,
            )

            ar = MagicMock()
            ar.bookmark.sort = [1]

            builder._ars = [ar]

            builder.keep_only_active_agents_ars()

            bookmark.update.assert_called_once_with([1])

        def test_no_ars(self):
            builder = ActiveResponseBuilder(
                logger=MagicMock(),
                active_agents=["1"],
                bookmark_file=MagicMock(),
            )

            builder._ars = []

            result = builder.keep_only_active_agents_ars()

            assert result is builder

    class TestDispatch:
        """Tests for dispatch."""

        @patch("wazuh.core.indexer.active_response.WazuhQueue")
        @patch(
            "wazuh.core.indexer.active_response.ActiveResponseHelpers.build_ar_messages"
        )
        def test_dispatch_success(self, mock_build, mock_queue):
            bookmark = ActiveResponseBookmark([1])

            mock_build.return_value = [
                ("1", {"msg": 1}, bookmark),
            ]

            mock_wq = MagicMock()
            mock_queue.return_value.__enter__.return_value = mock_wq

            builder = ActiveResponseBuilder(
                logger=MagicMock(),
                active_agents=["1"],
                bookmark_file=MagicMock(),
            )
            builder._ars = [MagicMock()]

            result = builder.dispatch()

            assert result is builder
            mock_wq.send_msg_to_agent.assert_called_once()
            builder._bookmark_file.update.assert_called_once_with([1])

        @patch(
            "wazuh.core.indexer.active_response.ActiveResponseHelpers.build_ar_messages",
            return_value=[],
        )
        def test_dispatch_no_messages(self, mock_build):
            builder = ActiveResponseBuilder(
                logger=MagicMock(),
                active_agents=["1"],
                bookmark_file=MagicMock(),
            )

            result = builder.dispatch()

            assert result is builder

        @patch("wazuh.core.indexer.active_response.WazuhQueue")
        @patch(
            "wazuh.core.indexer.active_response.ActiveResponseHelpers.build_ar_messages"
        )
        def test_dispatch_handles_error(self, mock_build, mock_queue):
            from wazuh.core.exception import WazuhError

            bookmark = ActiveResponseBookmark([1])

            mock_build.return_value = [
                ("1", {"msg": 1}, bookmark),
            ]

            mock_wq = MagicMock()
            mock_wq.send_msg_to_agent.side_effect = WazuhError(1)

            mock_queue.return_value.__enter__.return_value = mock_wq

            logger = MagicMock()

            builder = ActiveResponseBuilder(
                logger=logger,
                active_agents=["1"],
                bookmark_file=MagicMock(),
            )
            builder._ars = [MagicMock()]

            builder.dispatch()

            logger.error.assert_called_once()
            builder._bookmark_file.update.assert_called_once_with([1])


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
            mock_builder.keep_only_active_agents_ars.assert_called_once()
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
