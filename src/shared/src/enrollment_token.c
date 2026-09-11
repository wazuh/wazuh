/*
 * Copyright (C) 2015, Wazuh Inc.
 * September 8, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* Codec of the agent enrollment token: a compact JSON object
 * {"ver":1,"adr":...,"pin"|"ca":...,"key":...} wrapped in unpadded base64url, plus the HKDF
 * that turns its credential secret into the HS256 key of a `wazuh-enroll+jwt`. The
 * derivation is byte for byte the one of shared_modules/utils/jwt/enrollKeyDerivation.hpp,
 * with its own info label, so the C and the C++ sides can never drift.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/pem.h>
#include <openssl/sha.h>

#include "cJSON.h"
#include "shared.h"
#include "b64url_op.h"
#include "x509_op.h"
#include "enrollment_token.h"

/* Info label of the HKDF that derives the key of a token credential */
#define W_ETOKEN_HKDF_LABEL "WAZUH-ENROLL-TOKEN-KEY"

/* Version byte appended to the info label */
#define W_ETOKEN_HKDF_VERSION 0x01

/* Salt of the HKDF: that many zero bytes */
#define W_ETOKEN_HKDF_SALT_BYTES 32

/* Growable text buffer, only used to assemble the output of w_etoken_describe() */
typedef struct {
    char *text;
    size_t len;
    size_t cap;
} etoken_buf;

/* Pieces of an `adr` value, all pointing into the original string */
typedef struct {
    const char *host;   /* Host, without the brackets of an IPv6 literal */
    size_t host_len;
    int bracketed;      /* Whether the host was written between square brackets */
    int has_port;
    long port;
    int has_prefix;     /* Whether a '/' followed the authority */
    const char *prefix; /* Text after that '/', possibly empty */
} etoken_adr;

static int buf_append(etoken_buf *buf, const char *text, size_t len)
{
    if (buf->len + len + 1 > buf->cap) {
        size_t cap = (buf->cap == 0) ? 256 : buf->cap;
        char *grown = NULL;

        while (cap < buf->len + len + 1) {
            cap *= 2;
        }

        if ((grown = (char *) realloc(buf->text, cap)) == NULL) {
            return -1;
        }

        buf->text = grown;
        buf->cap = cap;
    }

    memcpy(buf->text + buf->len, text, len);
    buf->len += len;
    buf->text[buf->len] = '\0';

    return 0;
}

static int buf_append_str(etoken_buf *buf, const char *text)
{
    return buf_append(buf, text, strlen(text));
}

/* Lowercase hexadecimal of a byte string. `out` needs 2 * len + 1 bytes */
static void etoken_hex(const uint8_t *in, size_t len, char *out)
{
    static const char digits[] = "0123456789abcdef";
    size_t i;

    for (i = 0; i < len; i++) {
        out[i * 2] = digits[in[i] >> 4];
        out[i * 2 + 1] = digits[in[i] & 0x0F];
    }

    out[len * 2] = '\0';
}

/* Characters allowed in a path prefix segment and in an IPv6 zone identifier */
static int adr_is_prefix_char(char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
           c == '.' || c == '_' || c == '~' || c == '-';
}

/* Whether a slice is a DNS name: dot separated labels of [A-Za-z0-9-], 1 to 63 characters
 * each, never starting or ending with '-', 253 characters at most in total.
 */
static int adr_is_dns_name(const char *host, size_t len)
{
    size_t label = 0;
    size_t i;

    if (len == 0 || len > 253) {
        return 0;
    }

    for (i = 0; i < len; i++) {
        char c = host[i];

        if (c == '.') {
            if (label == 0 || host[i - 1] == '-') {
                return 0;
            }

            label = 0;
            continue;
        }

        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
              c == '-')) {
            return 0;
        }

        if (label == 0 && c == '-') {
            return 0;
        }

        if (++label > 63) {
            return 0;
        }
    }

    /* No trailing dot and no label ending in '-' */
    return (label != 0 && host[len - 1] != '-');
}

/* Whether a slice is an IP literal of exactly `want_len` bytes (4 for IPv4, 16 for IPv6).
 * OpenSSL is the parser here so that this file needs no POSIX networking call.
 */
static int adr_is_ip(const char *text, size_t len, int want_len)
{
    ASN1_OCTET_STRING *ip = NULL;
    char buf[64];
    int valid = 0;

    if (len == 0 || len >= sizeof(buf)) {
        return 0;
    }

    memcpy(buf, text, len);
    buf[len] = '\0';

    if ((ip = a2i_IPADDRESS(buf)) == NULL) {
        return 0;
    }

    valid = (ASN1_STRING_length(ip) == want_len);
    ASN1_OCTET_STRING_free(ip);

    return valid;
}

/* Split and validate an `adr` value against the <endpoint> grammar
 * host[:port][/[prefix]]: no scheme, host is a DNS name, an IPv4 dotted quad or an IPv6
 * literal between square brackets whose zone identifier is percent encoded as "%25", port
 * is 1 to 65535 in decimal and the prefix holds only [A-Za-z0-9._~-] and '/' separators.
 * Returns 0 when the value is valid, -1 otherwise.
 */
static int adr_parse(const char *adr, etoken_adr *out)
{
    const char *p = adr;
    const char *q = NULL;

    memset(out, 0, sizeof(*out));

    if (adr == NULL) {
        return -1;
    }

    if (*p == '[') {
        if ((q = strchr(p, ']')) == NULL) {
            return -1;
        }

        out->host = p + 1;
        out->host_len = (size_t) (q - p - 1);
        out->bracketed = 1;
        p = q + 1;
    } else {
        for (q = p; *q != '\0' && *q != ':' && *q != '/'; q++) {
        }

        out->host = p;
        out->host_len = (size_t) (q - p);
        p = q;
    }

    if (*p == ':') {
        p++;

        for (q = p; *q >= '0' && *q <= '9'; q++) {
        }

        /* No empty port, no sign, no value that could overflow the range check */
        if (q == p || (size_t) (q - p) > 5 || (*q != '\0' && *q != '/')) {
            return -1;
        }

        out->port = strtol(p, NULL, 10);

        if (out->port < 1 || out->port > 65535) {
            return -1;
        }

        out->has_port = 1;
        p = q;
    }

    if (*p == '/') {
        out->has_prefix = 1;
        out->prefix = p + 1;

        for (q = out->prefix; *q != '\0'; q++) {
            if (!adr_is_prefix_char(*q) && *q != '/') {
                return -1;
            }
        }
    } else if (*p != '\0') {
        return -1;
    }

    if (out->bracketed) {
        const char *end = out->host + out->host_len;
        const char *pct = (const char *) memchr(out->host, '%', out->host_len);
        size_t addr_len = out->host_len;

        if (pct != NULL) {
            /* A link-local zone identifier must be written as "%25<zone>" */
            if (end - pct < 4 || pct[1] != '2' || pct[2] != '5') {
                return -1;
            }

            for (q = pct + 3; q < end; q++) {
                if (!adr_is_prefix_char(*q)) {
                    return -1;
                }
            }

            addr_len = (size_t) (pct - out->host);
        }

        return adr_is_ip(out->host, addr_len, 16) ? 0 : -1;
    }

    return (adr_is_dns_name(out->host, out->host_len) ||
            adr_is_ip(out->host, out->host_len, 4)) ? 0 : -1;
}

/* Rewrite an `adr` value in its canonical form: the default port and the default prefix are
 * dropped, an explicitly empty prefix ("host/", which means "no prefix") is kept. Returns a
 * newly allocated string, or NULL when the value is not valid.
 */
static char *adr_normalise(const char *adr)
{
    etoken_adr parsed;
    etoken_buf buf = {NULL, 0, 0};

    if (adr_parse(adr, &parsed) != 0) {
        return NULL;
    }

    if (parsed.bracketed) {
        if (buf_append_str(&buf, "[") != 0 ||
            buf_append(&buf, parsed.host, parsed.host_len) != 0 ||
            buf_append_str(&buf, "]") != 0) {
            goto error;
        }
    } else if (buf_append(&buf, parsed.host, parsed.host_len) != 0) {
        goto error;
    }

    if (parsed.has_port && parsed.port != W_ETOKEN_DEFAULT_PORT) {
        char port[24];

        snprintf(port, sizeof(port), ":%ld", parsed.port);

        if (buf_append_str(&buf, port) != 0) {
            goto error;
        }
    }

    if (parsed.has_prefix && strcmp(parsed.prefix, W_ETOKEN_DEFAULT_PREFIX) != 0 &&
        strcmp(parsed.prefix, W_ETOKEN_DEFAULT_PREFIX "/") != 0) {
        if (buf_append_str(&buf, "/") != 0 || buf_append_str(&buf, parsed.prefix) != 0) {
            goto error;
        }
    }

    return buf.text;

error:
    free(buf.text);

    return NULL;
}

char *w_etoken_encode(const w_etoken_t *token)
{
    cJSON *root = NULL;
    char *adr = NULL;
    char *json = NULL;
    char *pin = NULL;
    char *key = NULL;
    char *out = NULL;

    if (token == NULL || token->ver != 1) {
        return NULL;
    }

    /* Exactly one anchor */
    if ((token->has_pin != 0) == (token->ca_pem != NULL)) {
        return NULL;
    }

    if ((adr = adr_normalise(token->adr)) == NULL) {
        return NULL;
    }

    if ((root = cJSON_CreateObject()) == NULL) {
        goto end;
    }

    /* cJSON keeps the insertion order, which is the order the format mandates */
    if (cJSON_AddNumberToObject(root, "ver", 1) == NULL ||
        cJSON_AddStringToObject(root, "adr", adr) == NULL) {
        goto end;
    }

    if (token->has_pin) {
        if ((pin = w_b64url_encode(token->pin, W_ETOKEN_PIN_BYTES)) == NULL ||
            cJSON_AddStringToObject(root, "pin", pin) == NULL) {
            goto end;
        }
    } else if (cJSON_AddStringToObject(root, "ca", token->ca_pem) == NULL) {
        goto end;
    }

    if (token->has_key) {
        uint8_t material[W_ETOKEN_KEY_BYTES];

        memcpy(material, token->id, W_ETOKEN_ID_BYTES);
        memcpy(material + W_ETOKEN_ID_BYTES, token->secret, W_ETOKEN_SECRET_BYTES);
        key = w_b64url_encode(material, sizeof(material));
        OPENSSL_cleanse(material, sizeof(material));

        if (key == NULL || cJSON_AddStringToObject(root, "key", key) == NULL) {
            goto end;
        }
    }

    if ((json = cJSON_PrintUnformatted(root)) == NULL) {
        goto end;
    }

    out = w_b64url_encode((const uint8_t *) json, strlen(json));

end:

    if (json != NULL) {
        OPENSSL_cleanse(json, strlen(json));
        cJSON_free(json);
    }

    if (key != NULL) {
        OPENSSL_cleanse(key, strlen(key));
        free(key);
    }

    cJSON_Delete(root);
    free(pin);
    free(adr);

    return out;
}

w_etoken_error_t w_etoken_decode(const char *text, w_etoken_t *out)
{
    uint8_t *raw = NULL;
    size_t raw_len = 0;
    char *json = NULL;
    cJSON *root = NULL;
    cJSON *item = NULL;
    cJSON *ver = NULL;
    cJSON *adr = NULL;
    cJSON *pin = NULL;
    cJSON *ca = NULL;
    cJSON *key = NULL;
    uint8_t *bytes = NULL;
    size_t bytes_len = 0;
    size_t json_len = 0;
    etoken_adr parsed;
    w_etoken_error_t result = ETOKEN_MALFORMED;

    if (out == NULL) {
        return ETOKEN_MALFORMED;
    }

    memset(out, 0, sizeof(*out));

    if (text == NULL || w_b64url_decode(text, &raw, &raw_len) != 0) {
        return ETOKEN_MALFORMED;
    }

    /* An embedded NUL is not a token, and it has to be refused HERE rather than left to the parser.
     * cJSON takes the length of the document from strlen(), so everything after a NUL would never
     * be looked at: `require_null_terminated` below would validate only the prefix, the member
     * check would only see the prefix's members, and the cleanse at the end would wipe only the
     * prefix -- leaving the rest of a credential in freed memory. It would also mean unlimited
     * different texts decoding to one token, which is precisely what the codec promises cannot
     * happen (b64url_op.h: "two different texts can therefore never decode to the same bytes").
     * That promise holds at the base64 layer; this is what makes it hold at the JSON layer too
     * (issue #39133).
     */
    if (memchr(raw, '\0', raw_len) != NULL) {
        OPENSSL_cleanse(raw, raw_len);
        free(raw);
        return ETOKEN_MALFORMED;
    }

    if ((json = (char *) malloc(raw_len + 1)) == NULL) {
        OPENSSL_cleanse(raw, raw_len);
        free(raw);
        return ETOKEN_MALFORMED;
    }

    memcpy(json, raw, raw_len);
    json[raw_len] = '\0';
    json_len = raw_len;
    OPENSSL_cleanse(raw, raw_len);
    free(raw);

    if ((root = cJSON_ParseWithOpts(json, NULL, 1)) == NULL || !cJSON_IsObject(root)) {
        goto end;
    }

    /* The member set must be exactly the allowed one, with no duplicate and no surprise
     * type: anything else is a token this version must not try to interpret.
     */
    for (item = root->child; item != NULL; item = item->next) {
        cJSON **slot = NULL;
        int is_number = 0;

        if (item->string == NULL) {
            goto end;
        }

        if (strcmp(item->string, "ver") == 0) {
            slot = &ver;
            is_number = 1;
        } else if (strcmp(item->string, "adr") == 0) {
            slot = &adr;
        } else if (strcmp(item->string, "pin") == 0) {
            slot = &pin;
        } else if (strcmp(item->string, "ca") == 0) {
            slot = &ca;
        } else if (strcmp(item->string, "key") == 0) {
            slot = &key;
        } else {
            goto end;
        }

        if (*slot != NULL) {
            goto end;
        }

        if (is_number ? !cJSON_IsNumber(item) : !cJSON_IsString(item)) {
            goto end;
        }

        *slot = item;
    }

    if (ver == NULL || cJSON_GetNumberValue(ver) != 1) {
        result = ETOKEN_VERSION;
        goto end;
    }

    if (pin == NULL && ca == NULL) {
        result = ETOKEN_NO_ANCHOR;
        goto end;
    }

    if (pin != NULL && ca != NULL) {
        result = ETOKEN_BOTH_ANCHORS;
        goto end;
    }

    if (adr == NULL || adr_parse(adr->valuestring, &parsed) != 0) {
        result = ETOKEN_BAD_ADR;
        goto end;
    }

    if (pin != NULL) {
        if (w_b64url_decode(pin->valuestring, &bytes, &bytes_len) != 0 ||
            bytes_len != W_ETOKEN_PIN_BYTES) {
            result = ETOKEN_BAD_PIN;
            goto end;
        }

        memcpy(out->pin, bytes, W_ETOKEN_PIN_BYTES);
        out->has_pin = 1;
        free(bytes);
        bytes = NULL;
    }

    if (key != NULL) {
        if (w_b64url_decode(key->valuestring, &bytes, &bytes_len) != 0 ||
            bytes_len != W_ETOKEN_KEY_BYTES) {
            result = ETOKEN_BAD_KEY;
            goto end;
        }

        memcpy(out->id, bytes, W_ETOKEN_ID_BYTES);
        memcpy(out->secret, bytes + W_ETOKEN_ID_BYTES, W_ETOKEN_SECRET_BYTES);
        out->has_key = 1;
        OPENSSL_cleanse(bytes, bytes_len);
        free(bytes);
        bytes = NULL;
    }

    out->ver = 1;

    /* `adr` is kept exactly as written: normalising is an encoding step only */
    if ((out->adr = strdup(adr->valuestring)) == NULL) {
        goto end;
    }

    if (ca != NULL && (out->ca_pem = strdup(ca->valuestring)) == NULL) {
        goto end;
    }

    result = ETOKEN_OK;

end:

    if (bytes != NULL) {
        OPENSSL_cleanse(bytes, bytes_len);
        free(bytes);
    }

    cJSON_Delete(root);

    if (json != NULL) {
        /* The decoded length, not strlen(): the two agree because a blob with an embedded NUL was
         * refused above, and saying so explicitly keeps the wipe complete if that ever changes */
        OPENSSL_cleanse(json, json_len);
        free(json);
    }

    if (result != ETOKEN_OK) {
        w_etoken_free(out);
    }

    return result;
}

void w_etoken_free(w_etoken_t *token)
{
    if (token == NULL) {
        return;
    }

    free(token->adr);
    free(token->ca_pem);
    OPENSSL_cleanse(token->secret, sizeof(token->secret));
    memset(token, 0, sizeof(*token));
}

/* Append the contents of a memory BIO behind a label, as one line */
static int describe_append_bio(etoken_buf *buf, const char *label, BIO *mem)
{
    char *data = NULL;
    long len = BIO_get_mem_data(mem, &data);

    if (len < 0 || data == NULL) {
        return -1;
    }

    if (buf_append_str(buf, label) != 0 || buf_append(buf, data, (size_t) len) != 0) {
        return -1;
    }

    return buf_append_str(buf, "\n");
}

static int describe_append_name(etoken_buf *buf, const char *label, X509_NAME *name)
{
    BIO *mem = NULL;
    int result = -1;

    if (name == NULL || (mem = BIO_new(BIO_s_mem())) == NULL) {
        return -1;
    }

    if (X509_NAME_print_ex(mem, name, 0, XN_FLAG_ONELINE) >= 0) {
        result = describe_append_bio(buf, label, mem);
    }

    BIO_free(mem);

    return result;
}

static int describe_append_time(etoken_buf *buf, const char *label, const ASN1_TIME *when)
{
    BIO *mem = NULL;
    int result = -1;

    if (when == NULL || (mem = BIO_new(BIO_s_mem())) == NULL) {
        return -1;
    }

    if (ASN1_TIME_print(mem, when) == 1) {
        result = describe_append_bio(buf, label, mem);
    }

    BIO_free(mem);

    return result;
}

static int describe_append_fingerprint(etoken_buf *buf, X509 *cert)
{
    unsigned char *der = NULL;
    int der_len = 0;
    uint8_t digest[SHA256_DIGEST_LENGTH];
    char hex[SHA256_DIGEST_LENGTH * 2 + 1];

    if ((der_len = i2d_X509(cert, &der)) <= 0 || der == NULL) {
        return -1;
    }

    SHA256(der, (size_t) der_len, digest);
    OPENSSL_free(der);
    etoken_hex(digest, sizeof(digest), hex);

    if (buf_append_str(buf, "ca sha256: ") != 0 || buf_append_str(buf, hex) != 0) {
        return -1;
    }

    return buf_append_str(buf, "\n");
}

/* Describe an embedded CA: who it is, how long it lasts and which certificate it is */
static int describe_ca(etoken_buf *buf, const char *pem)
{
    BIO *mem = NULL;
    X509 *cert = NULL;
    int result = -1;

    if ((mem = BIO_new_mem_buf(pem, -1)) == NULL) {
        return -1;
    }

    cert = PEM_read_bio_X509(mem, NULL, NULL, NULL);
    BIO_free(mem);

    if (cert == NULL) {
        return buf_append_str(buf, "ca: unreadable\n");
    }

    if (describe_append_name(buf, "ca subject: ", X509_get_subject_name(cert)) == 0 &&
        describe_append_name(buf, "ca issuer: ", X509_get_issuer_name(cert)) == 0 &&
        describe_append_time(buf, "ca not before: ", X509_get0_notBefore(cert)) == 0 &&
        describe_append_time(buf, "ca not after: ", X509_get0_notAfter(cert)) == 0 &&
        describe_append_fingerprint(buf, cert) == 0) {
        result = 0;
    }

    X509_free(cert);

    return result;
}

char *w_etoken_describe(const w_etoken_t *token)
{
    etoken_buf buf = {NULL, 0, 0};
    char line[32];

    if (token == NULL) {
        return NULL;
    }

    snprintf(line, sizeof(line), "ver: %d\n", token->ver);

    if (buf_append_str(&buf, line) != 0 || buf_append_str(&buf, "adr: ") != 0 ||
        buf_append_str(&buf, (token->adr != NULL) ? token->adr : "") != 0 ||
        buf_append_str(&buf, "\n") != 0) {
        goto error;
    }

    if (token->has_pin) {
        char hex[W_ETOKEN_PIN_BYTES * 2 + 1];

        etoken_hex(token->pin, W_ETOKEN_PIN_BYTES, hex);

        if (buf_append_str(&buf, "pin: ") != 0 || buf_append_str(&buf, hex) != 0 ||
            buf_append_str(&buf, "\n") != 0) {
            goto error;
        }
    }

    if (token->ca_pem != NULL && describe_ca(&buf, token->ca_pem) != 0) {
        goto error;
    }

    /* The identifier, the secret and their base64url never reach a log or a terminal */
    if (buf_append_str(&buf, token->has_key ? "credential: present\n"
                                            : "credential: absent\n") != 0) {
        goto error;
    }

    return buf.text;

error:
    free(buf.text);

    return NULL;
}

int w_etoken_derive_key(const uint8_t secret[W_ETOKEN_SECRET_BYTES],
                        uint8_t out[W_ETOKEN_KEY_BYTES])
{
    static const char label[] = W_ETOKEN_HKDF_LABEL;
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *ctx = NULL;
    OSSL_PARAM params[6];
    uint8_t ikm[W_ETOKEN_SECRET_BYTES];
    uint8_t info[sizeof(label)];
    uint8_t salt[W_ETOKEN_HKDF_SALT_BYTES];
    char digest[] = "SHA2-256";
    int mode = EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND;
    int result = -1;

    if (secret == NULL || out == NULL) {
        return -1;
    }

    memcpy(ikm, secret, sizeof(ikm));
    memcpy(info, label, sizeof(label) - 1);
    info[sizeof(label) - 1] = W_ETOKEN_HKDF_VERSION;
    memset(salt, 0, sizeof(salt));

    if ((kdf = EVP_KDF_fetch(NULL, "HKDF", NULL)) == NULL) {
        goto end;
    }

    if ((ctx = EVP_KDF_CTX_new(kdf)) == NULL) {
        goto end;
    }

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest, 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, ikm, sizeof(ikm));
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, salt, sizeof(salt));
    params[3] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, info, sizeof(info));
    params[4] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
    params[5] = OSSL_PARAM_construct_end();

    if (EVP_KDF_derive(ctx, out, W_ETOKEN_KEY_BYTES, params) == 1) {
        result = 0;
    }

end:
    EVP_KDF_CTX_free(ctx);
    EVP_KDF_free(kdf);
    OPENSSL_cleanse(ikm, sizeof(ikm));

    return result;
}

const char *w_etoken_strerror(w_etoken_error_t err)
{
    switch (err) {
    case ETOKEN_OK:
        return "no error";
    case ETOKEN_MALFORMED:
        return "malformed token";
    case ETOKEN_VERSION:
        return "unsupported token version";
    case ETOKEN_NO_ANCHOR:
        return "the token carries no certificate anchor";
    case ETOKEN_BOTH_ANCHORS:
        return "the token carries both a pin and a CA";
    case ETOKEN_BAD_PIN:
        return "the pin is not a 32 byte digest";
    case ETOKEN_BAD_KEY:
        return "the credential is not 32 bytes long";
    case ETOKEN_BAD_ADR:
        return "the address does not follow the endpoint grammar";
    default:
        return "unknown error";
    }
}
