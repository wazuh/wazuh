# CTI OAuth Providers

## Overview

The Content Manager module includes OAuth 2.0 authentication support for accessing protected CTI APIs. This is implemented through two provider classes that handle the OAuth 2.0 Token Exchange flow (RFC 8693) with HMAC-signed URLs.

## Components

### CTICredentialsProvider

The [CTICredentialsProvider](../../src/components/ctiCredentialsProvider.hpp) is responsible for fetching and managing OAuth 2.0 credentials from the Wazuh Indexer.

#### Features

- **Automatic credential fetching** from Wazuh Indexer's `/_wazuh/cti/credentials` endpoint
- **Thread-safe access** to credentials using mutex protection
- **Background refresh thread** that automatically refreshes tokens before they expire (<5 minutes remaining)
- **Exponential backoff retry** mechanism (up to 3 attempts) for failed requests
- **Memory-only storage** - credentials are never persisted to disk

#### Configuration

```cpp
nlohmann::json config = {
    {"indexer", {
        {"url", "http://localhost:9200"},
        {"credentialsEndpoint", "/_wazuh/cti/credentials"},  // Optional, default shown
        {"pollInterval", 60},                                 // Optional, seconds
        {"timeout", 5000},                                    // Optional, milliseconds
        {"retryAttempts", 3}                                  // Optional, default shown
    }}
};

auto credentialsProvider = std::make_shared<CTICredentialsProvider>(
    httpRequest,
    config
);
```

#### Usage

```cpp
// Get access token (automatically refreshed if needed)
std::string accessToken = credentialsProvider->getAccessToken();

// Check token expiration
uint64_t expiresIn = credentialsProvider->getExpiresIn();
```

### CTISignedUrlProvider

The [CTISignedUrlProvider](../../src/components/ctiSignedUrlProvider.hpp) handles OAuth 2.0 Token Exchange to convert access tokens into HMAC-signed URLs.

#### Features

- **OAuth 2.0 Token Exchange** (RFC 8693) with CTI Console
- **Signed URL caching** to minimize token exchange requests (5-minute expiration by default)
- **Thread-safe cache** with automatic cleanup of expired URLs
- **Configurable cache behavior** - can be disabled if needed
- **Automatic token refresh** when signed URLs expire

#### Configuration

```cpp
nlohmann::json config = {
    {"tokenExchange", {
        {"consoleUrl", "https://console.wazuh.com"},
        {"tokenEndpoint", "/api/v1/instances/token/exchange"},  // Optional, default shown
        {"cacheSignedUrls", true},                               // Optional, default shown
        {"signedUrlLifetime", 300}                               // Optional, seconds, default shown
    }}
};

auto signedUrlProvider = std::make_shared<CTISignedUrlProvider>(
    httpRequest,
    config
);
```

#### Usage

```cpp
// Exchange access token for signed URL
std::string originalUrl = "https://cti.wazuh.com/api/v1/catalog/contexts/vd_1.0.0/consumers/vd_5.0.0";
std::string accessToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...";

std::string signedUrl = signedUrlProvider->getSignedUrl(originalUrl, accessToken);
// Returns: "https://cti.wazuh.com/api/v1/catalog/contexts/vd_1.0.0/consumers/vd_5.0.0?verify=hmac_signature"
```

## OAuth 2.0 Flow

The complete OAuth flow for CTI content download works as follows:

```
┌─────────────────┐
│ Content Manager │
└────────┬────────┘
         │
         │ 1. Request credentials
         v
┌─────────────────────────┐
│ CTICredentialsProvider  │
└────────┬────────────────┘
         │
         │ 2. GET /_wazuh/cti/credentials
         v
┌─────────────────┐
│ Wazuh Indexer   │
└────────┬────────┘
         │
         │ 3. Return access_token + expires_in
         v
┌─────────────────────────┐
│ CTICredentialsProvider  │◄─── Background refresh thread
└────────┬────────────────┘
         │
         │ 4. Provide access_token
         v
┌──────────────────────┐
│ CTISignedUrlProvider │
└────────┬─────────────┘
         │
         │ 5. POST /api/v1/instances/token/exchange
         │    {
         │      "subject_token": "access_token",
         │      "resource": "original_url"
         │    }
         v
┌─────────────────┐
│ CTI Console     │
└────────┬────────┘
         │
         │ 6. Return signed URL + expires_in
         v
┌──────────────────────┐
│ CTISignedUrlProvider │◄─── Cache (5 min)
└────────┬─────────────┘
         │
         │ 7. Provide signed URL
         v
┌─────────────────┐
│ CtiDownloader   │
└────────┬────────┘
         │
         │ 8. HTTP request with signed URL
         v
┌─────────────────┐
│ CTI API         │
└─────────────────┘
```

## Security Considerations

### Token Lifetime

- **Access tokens**: Typically valid for 1 hour
  - Automatically refreshed when <5 minutes remaining
  - Never persisted to disk
  - Thread-safe access

- **Signed URLs**: Valid for 5 minutes by default
  - Cached to reduce token exchange overhead
  - Automatically refreshed when expired
  - Cache can be disabled if needed

### Transport Security

- All OAuth communications should use HTTPS in production
- SSL/TLS certificate verification is enforced by default
- HTTP is only supported for development/testing

### Credential Storage

- **Credentials are never stored on disk**
- Access tokens remain in memory only
- Background refresh ensures tokens are always valid
- Process termination clears all credentials

## Error Handling

### Credential Provider Errors

- **401 Unauthorized**: Invalid Indexer credentials
- **Connection failures**: Automatic retry with exponential backoff (3 attempts)
- **Token expiration**: Automatic refresh before expiry
- **JSON parsing errors**: Thrown as `std::runtime_error`

### Signed URL Provider Errors

- **Token exchange failures**: Propagated to caller
- **Invalid token format**: Thrown as `std::runtime_error`
- **Cache lookup failures**: Falls back to fresh token exchange
- **Expired tokens**: Automatic refresh and retry

## Backward Compatibility

OAuth authentication is **completely optional**. When providers are not configured (or set to `nullptr`), downloaders behave exactly as before:

```cpp
// Without OAuth (backward compatible)
auto downloader = std::make_shared<CtiOffsetDownloader>(httpRequest);

// With OAuth
auto downloader = std::make_shared<CtiOffsetDownloader>(
    httpRequest,
    credentialsProvider,
    signedUrlProvider
);
```

## References

- [RFC 8693 - OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693)
- [RFC 8628 - OAuth 2.0 Device Authorization Grant](https://datatracker.ietf.org/doc/html/rfc8628)
- [CTI Offset Downloader Documentation](CTI_OFFSET_DOWNLOADER.md)
- [CTI Snapshot Downloader Documentation](CTI_SNAPSHOT_DOWNLOADER.md)
