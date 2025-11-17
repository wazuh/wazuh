# CTI OAuth Providers

## Overview

The Content Manager module includes OAuth 2.0 authentication support for accessing protected CTI APIs. This is implemented through two provider classes that handle the OAuth 2.0 Token Exchange flow (RFC 8693) with HMAC-signed URLs.

## Components

### CTICredentialsProvider

The [CTICredentialsProvider](../../src/components/ctiCredentialsProvider.hpp) is responsible for fetching and managing OAuth 2.0 credentials from the Wazuh Indexer.

#### Features

- **Automatic credential fetching** from Wazuh Indexer's `/_plugins/content-manager/subscription` endpoint
- **Thread-safe access** to credentials using mutex protection
- **Background refresh thread** that automatically refreshes tokens on each poll interval
- **Exponential backoff retry** mechanism (up to 3 attempts) for failed requests
- **Memory-only storage** - credentials are never persisted to disk

#### Configuration

```cpp
nlohmann::json config = {
    {"indexer", {
        {"url", "http://localhost:9200"},
        {"credentialsEndpoint", "/_plugins/content-manager/subscription"},  // Optional, default shown
        {"pollInterval", 60},                                                // Optional, seconds
        {"timeout", 5000},                                                   // Optional, milliseconds
        {"retryAttempts", 3}                                                 // Optional, default shown
    }}
};

auto credentialsProvider = std::make_shared<CTICredentialsProvider>(
    httpRequest,
    config
);
```

#### Usage

```cpp
// Get access token (automatically fetched if not available)
std::string accessToken = credentialsProvider->getAccessToken();
```

### CTIProductsProvider

The [CTIProductsProvider](../../src/components/ctiProductsProvider.hpp) fetches subscription information from CTI Console to determine which products the instance is subscribed to, with support for filtering products by type.

#### Features

- **Fetch subscription data** from Console's `/api/v1/instances/me` endpoint using Bearer token
- **Parse organization and plan** information
- **Extract product metadata** including stable identifiers and resource URLs
- **Filter products by type** (e.g., "catalog:consumer:decoders" for Engine module)
- **Filter catalog products** that require token exchange
- **Cache subscription data** to minimize API calls
- **Thread-safe access** to subscription information

#### Configuration

```cpp
nlohmann::json config = {
    {"console", {
        {"url", "https://console.wazuh.com"},
        {"instancesEndpoint", "/api/v1/instances/me"},     // Optional, default shown
        {"timeout", 5000},                                  // Optional, milliseconds
        {"productType", "catalog:consumer:decoders"}        // Optional, filter by product type
    }}
};

auto productsProvider = std::make_shared<CTIProductsProvider>(
    httpRequest,
    config
);
```

#### Product Type Filtering

The `productType` configuration field allows filtering products by their type. This is particularly useful for modules that need specific types of content.

**Example**: For the Engine module downloading decoders, configure:
```cpp
{"productType", "catalog:consumer:decoders"}
```

This ensures `getCatalogProducts()` returns only decoder products, excluding rules, integrations, and other content types.

#### Usage

```cpp
// Set access token from credentials provider
productsProvider->setAccessToken(accessToken);

// Fetch subscription information
auto subscription = productsProvider->fetchSubscription();

// Access organization info
std::cout << "Organization: " << subscription.organization.name << "\n";

// Iterate through plans and products
for (const auto& plan : subscription.plans) {
    std::cout << "Plan: " << plan.name << "\n";
    for (const auto& product : plan.products) {
        if (product.type == "catalog:consumer") {
            // This product has a resource URL for token exchange
            std::cout << "  Product: " << product.identifier << "\n";
            std::cout << "  Resource: " << product.resource << "\n";
        }
    }
}

// Or get only catalog products filtered by configured type
auto catalogProducts = productsProvider->getCatalogProducts();
for (const auto& product : catalogProducts) {
    // All products here match the configured productType
    // e.g., if productType="catalog:consumer:decoders", only decoder products are returned
    std::string signedUrl = signedUrlProvider->getSignedUrl(product.resource, accessToken);
}
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
// Exchange access token for signed URL (using resource from product)
std::string signedUrl = signedUrlProvider->getSignedUrl(product.resource, accessToken);
// Returns: "https://cti.wazuh.com/api/v1/catalog/...?verify=hmac_signature"
```

## Subscription Response Example

The Console API returns subscription data with product type information:

```json
{
  "data": {
    "organization": {
      "identifier": "org-123",
      "name": "ACME S.L.",
      "avatar": "https://acme.sl/avatar.png"
    },
    "plans": [
      {
        "identifier": "plan-pro",
        "name": "Pro Plan Deluxe",
        "description": "Professional tier subscription",
        "products": [
          {
            "identifier": "vulnerabilities-pro",
            "type": "catalog:consumer:decoders",
            "name": "Vulnerabilities Pro",
            "description": "Real-time vulnerability intelligence decoders",
            "resource": "https://cti.wazuh.com/api/v1/catalog/.../decoders"
          },
          {
            "identifier": "malware-signatures",
            "type": "catalog:consumer:rules",
            "name": "Malware Signatures",
            "description": "Malware detection rules",
            "resource": "https://cti.wazuh.com/api/v1/catalog/.../rules"
          },
          {
            "identifier": "integration-connectors",
            "type": "catalog:consumer:integrations",
            "name": "Integration Connectors",
            "description": "Third-party API connectors",
            "resource": "https://cti.wazuh.com/api/v1/catalog/.../integrations"
          },
          {
            "identifier": "support-assistance",
            "type": "cloud:assistance",
            "name": "Support Assistance",
            "email": "support@wazuh.com",
            "phone": "+1-555-0100"
          }
        ]
      }
    ]
  }
}
```

## Complete OAuth 2.0 Flow

The complete OAuth flow for CTI content download now includes the new subscription step:

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
         │ 2. GET /_plugins/content-manager/subscription
         v
┌─────────────────┐
│ Wazuh Indexer   │
└────────┬────────┘
         │
         │ 3. Return access_token + token_type
         v
┌─────────────────────────┐
│ CTICredentialsProvider  │◄─── Background refresh thread
└────────┬────────────────┘
         │
         │ 4. Provide access_token
         v
┌──────────────────────┐
│ CTIProductsProvider  │
└────────┬─────────────┘
         │
         │ 5. GET /api/v1/instances/me
         │    Authorization: Bearer <access_token>
         v
┌──────────────┐
│ CTI Console  │
└────────┬─────┘
         │
         │ 6. Return subscription data:
         │    - Organization info
         │    - Plans and products
         │    - Resource URLs for each product
         v
┌──────────────────────┐
│ CTIProductsProvider  │
└────────┬─────────────┘
         │
         │ 7. Extract product resources
         v
┌──────────────────────┐
│ CTISignedUrlProvider │
└────────┬─────────────┘
         │
         │ 8. POST /api/v1/instances/token/exchange
         │    {
         │      "subject_token": "access_token",
         │      "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
         │      "resource": "<product.resource>"
         │    }
         v
┌─────────────────┐
│ CTI Console     │
└────────┬────────┘
         │
         │ 9. Return signed URL + expires_in
         v
┌──────────────────────┐
│ CTISignedUrlProvider │◄─── Cache (5 min)
└────────┬─────────────┘
         │
         │ 10. Return signed URL
         v
┌─────────────────┐
│ CtiDownloader   │
└────────┬────────┘
         │
         │ 11. Download CTI content using signed URL
         v
┌─────────────────┐
│ CTI API         │
└─────────────────┘
```

### Flow Summary

1. **CTICredentialsProvider** fetches OAuth credentials (access_token) from Wazuh Indexer
2. Background thread automatically refreshes tokens on each poll interval
3. **CTIProductsProvider** uses access_token to fetch subscription information from Console
4. Console returns organization details and list of subscribed products with their resource URLs
5. For each catalog product, **CTISignedUrlProvider** exchanges the access_token for a signed URL
6. Signed URL includes HMAC signature and has 5-minute expiration
7. **CtiDownloader** uses signed URL to download CTI content
8. Cached signed URLs are reused for performance

## Security Considerations

### Token Lifetime

- **Access tokens**: Lifetime managed by Wazuh Indexer
  - Automatically refreshed on each poll interval (default: 60 seconds)
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
