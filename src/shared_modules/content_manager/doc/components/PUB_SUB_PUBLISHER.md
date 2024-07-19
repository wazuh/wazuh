# Pub Sub Publisher stage

## Details

The [pub-sub publisher](../../src/components/pubSubPublisher.hpp) stage is part of the Content Manager orchestration and is in charge of publishing the Content Updater content data that will be then read by the consumers.

> Note: The `pub-sub` prefix makes reference to the [Publish-Subscribe pattern](https://github.com/wazuh/wazuh/issues/16786).

The content data includes:
- Content file paths: A list of paths of the files that hold the downloaded content from previous stages.
- Content Updater stages status: A list that summarizes which stages where executed in the orchestration along with their status (whether `ok` or `fail`).

It's important to note that if the list of paths is empty, meaning that there is no new content to process, the publishing is skipped.

The publication is made through a [router provider](../../../router/include/iRouterProvider.hpp) and into a channel, so that the channel subscribers will be able to consume the published content.

The published content data has the following structure:

```json
{
    "paths": [
        "<file_1_path>",
        "<file_2_path>",
        ...
        "<file_N_path>"
    ],
    "stageStatus": [
        {
            "stage": "<stage_A_name>",
            "status": "<stage_A_status>"
        },
        {
            "stage": "<stage_B_name>",
            "status": "<stage_B_status>"
        },
        ...
        {
            "stage": "<stage_N_name>",
            "status": "<stage_N_status>"
        }
    ]
}
```

For example, fetching some new content through the `ApiDownloader` downloader could generate the following data to be published:

```json
{
    "paths": [
        "/tmp/testProvider/contents/example.json"
    ],
    "stageStatus": [
        {
            "stage": "APIDownloader",
            "status": "ok"
        }
    ]
}
```

## Relation with the UpdaterContext

The context fields related to this stage are:

- `data`: Used to read both the content paths and the stages status.
- `spChannel`: Router provider instance used to publish the content data.
