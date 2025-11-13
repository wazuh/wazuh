# CTI Offset Downloader stage

## Details

The [CTI offset downloader](../../src/components/CtiOffsetDownloader.hpp) stage is part of the Content Manager orchestration and is in charge of downloading content from a CTI API to be then processed by the following stages. The downloaded content is stored in one or multiple output files, whose paths will be then published for the consumers to read.

The output content files will be stored in any of the following output directories:
- Downloads folder: If the input files are compressed.
- Contents folder: If the input files are not compressed.

The download process can be summarized as follows:
1. Get the last CTI API consumer offset. This is done by performing an HTTP GET query to CTI. This value will be used as the last possible offset to query.
2. Set the range of offsets to be downloaded, starting from `currentOffset` (set in the context) and with a range-width of `1000`. So, for example, if the current offset is equal to `N`, the range will be from offset `N` to offset `N + 1000`.
3. Download the offsets range from **step 2**. The download will be retried indefinitely if the server responds with an 5xx HTTP error code. The `currentOffset` isn't updated in this phase but in the processing callback.
4. Dump the downloaded offsets into an output file. This file path will be generated as `<output-folder>/<currentOffset>-<contentFileName>`.
5. Push the new file path (from **step 4**) to the context [data paths](../../src/components/updaterContext.hpp).
6. If the last possible offset (from **step 1**) has been downloaded, the process finishes. Otherwise, the process continues with the **step 2**.

### Download process example

Given the following conditions:
- Last possible offset: `3200`.
- Initial current offset: `0` (first execution ever).
- Content compressed: No.
- Output folder: `/tmp/`.
- Content filename: `data.json`.

The output files will be:
- `/tmp/contents/1000-data.json` (data from offsets 0 to 1000)
- `/tmp/contents/2000-data.json` (data from offsets 1000 to 2000)
- `/tmp/contents/3000-data.json` (data from offsets 2000 to 3000)
- `/tmp/contents/3200-data.json` (data from offsets 3000 to 3200)

## OAuth 2.0 Authentication (Optional)

The CTI Offset Downloader supports optional OAuth 2.0 authentication with token exchange for accessing protected CTI APIs. When enabled, the downloader can:

1. **Fetch OAuth credentials** from Wazuh Indexer (`/_wazuh/cti/credentials` endpoint)
2. **Exchange access tokens** for HMAC-signed URLs via CTI Console token exchange endpoint
3. **Cache signed URLs** (5-minute lifetime by default) to minimize token exchange requests
4. **Automatically refresh tokens** before they expire

### OAuth Configuration

OAuth authentication is configured by providing optional `CTICredentialsProvider` and `CTISignedUrlProvider` instances when instantiating the downloader:

```cpp
// Create OAuth providers
auto credentialsProvider = std::make_shared<CTICredentialsProvider>(
    httpRequest,
    indexerConfig  // Contains: url, username, password, ssl options
);

auto signedUrlProvider = std::make_shared<CTISignedUrlProvider>(
    httpRequest,
    tokenExchangeConfig  // Contains: consoleUrl, tokenEndpoint, cacheSignedUrls, signedUrlLifetime
);

// Create downloader with OAuth support
auto downloader = std::make_shared<CtiOffsetDownloader>(
    httpRequest,
    credentialsProvider,    // Optional: nullptr for no OAuth
    signedUrlProvider       // Optional: nullptr for no OAuth
);
```

### OAuth Flow

When OAuth is enabled, the download process is modified as follows:

1. **Before each HTTP request**, the downloader calls `getEffectiveUrl(originalUrl)`:
   - If no providers are configured (nullptr), returns the original URL (backward compatible)
   - Otherwise, gets an access token from the credentials provider
   - Exchanges the access token for a signed URL via the signed URL provider
   - Returns the signed URL to use for the request

2. **Token management**:
   - Access tokens are automatically refreshed when they expire (<5 minutes remaining)
   - Signed URLs are cached and reused until they expire (5 minutes by default)
   - Background threads handle automatic token refresh

3. **Error handling**:
   - Authentication failures are properly propagated
   - Retries follow the same logic as non-OAuth requests (5xx errors only)

### Backward Compatibility

OAuth is completely optional. When providers are not provided (or set to `nullptr`), the downloader behaves exactly as before, using the original URLs without any authentication transformation.

## Relation with the UpdaterContext

The context fields related to this stage are:

- `configData`
  + `url`: Used as the CTI API URL to download from. When OAuth is enabled, this URL is transformed into a signed URL before making requests.
  + `compressionType`: Used to determine whether the input file is compressed or not.
  + `contentfileName`: Used as name for the output content file.
- `downloadsFolder`: Used as output folder when the input file is compressed.
- `contentsFolder`: Used as output folder when the input file is not compressed.
- `data`: Used to read and update the paths under the `paths` key. The stage status is also updated on this member.
- `outputFolder`: Used as the destination file path base.
- `currentOffset`: Used as the first offset that will be fetched from the API. The next time the download begins from the offset read from the DB, only the processing data callback after a successful operation updates the value in the context.
