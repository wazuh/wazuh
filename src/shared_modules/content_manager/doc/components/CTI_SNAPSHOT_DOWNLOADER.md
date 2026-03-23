# CTI Snapshot Downloader stage

## Details

The [CTI snapshot downloader](../../src/components/CtiSnapshotDownloader.hpp) stage is part of the Content Manager orchestration and is in charge of downloading a content snapshot file from a CTI API to be then processed by the following stages. The downloaded file is assumed to be compressed and so is stored in the downloads folder.

The current offset is also updated with the last offset available within the snapshot. In that way, if a [CtiOffsetDownloader](CTI_OFFSET_DOWNLOADER.md) is used afterwards, it wont download the same offsets that were present on the snapshot file.

The download process can be summarized in two steps:
1. Get the last snapshot file URL from CTI. This is done by performing an HTTP GET query to the CTI base URL.
2. Download the snapshot file from the URL from **step 1**.

## OAuth 2.0 Authentication (Optional)

Similar to [CTI Offset Downloader](CTI_OFFSET_DOWNLOADER.md#oauth-20-authentication-optional), the CTI Snapshot Downloader also supports optional OAuth 2.0 authentication. When OAuth providers are configured, snapshot URLs are automatically transformed into HMAC-signed URLs before downloading.

```cpp
// Create downloader with OAuth support
auto downloader = std::make_shared<CtiSnapshotDownloader>(
    httpRequest,
    credentialsProvider,    // Optional: nullptr for no OAuth
    signedUrlProvider       // Optional: nullptr for no OAuth
);
```

For detailed information about OAuth configuration and flow, see the [OAuth section in CTI Offset Downloader documentation](CTI_OFFSET_DOWNLOADER.md#oauth-20-authentication-optional).

## Relation with the UpdaterContext

The context fields related to this stage are:

- `configData`
  + `url`: Used as the CTI API base URL to download from. When OAuth is enabled, snapshot URLs are transformed into signed URLs before making requests.
- `downloadsFolder`: Used as output folder for the snapshot file.
- `data`: Used to read and update the paths under the `paths` key. The stage status is also updated on this member.
