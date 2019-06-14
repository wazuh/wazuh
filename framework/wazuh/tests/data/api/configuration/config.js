
var config = {};

// Basic configuration

// Path
config.ossec_path = "/var/ossec";
// The host to bind the API to.
config.host = "0.0.0.0";
// TCP Port used by the API.
config.port = "55000";
// Use HTTP protocol over TLS/SSL. Values: yes, no.
config.https = "no";
// Use HTTP authentication. Values: yes, no.
config.basic_auth = "yes";
//In case the API run behind a proxy server, turn to "yes" this feature. Values: yes, no.
config.BehindProxyServer = "no";

// HTTPS Certificates
//config.https_key = "configuration/ssl/server.key"
//config.https_cert = "configuration/ssl/server.crt"
//config.https_use_ca = "no"
//config.https_ca = "configuration/ssl/ca.crt"

// Advanced configuration

// Values for API log: disabled, info, warning, error, debug (each level includes the previous level).
config.logs = "info";
// Cross-origin resource sharing. Values: yes, no.
config.cors = "yes";
// Cache (time in milliseconds)
config.cache_enabled = "yes";
config.cache_debug = "no";
config.cache_time = "750";
// Log path
config.log_path = config.ossec_path + "/logs/api.log";

// Option to force the use of authd to remove and add agents
config.use_only_authd = false;

// Option to drop privileges (run as ossec)
config.drop_privileges = true;

// Activate features still under development
config.experimental_features  = false;

/************************* SSL OPTIONS ****************************************/
// SSL protocol

// SSL protocol to use. All available secure protocols available at:
// https://www.openssl.org/docs/man1.0.2/ssl/ssl.html#DEALING-WITH-PROTOCOL-METHODS
config.secureProtocol = "TLSv1_2_method";
try {
    // Disable the use of SSLv3, TLSv1.1 and TLSv1.0. All available secureOptions at: 
    // https://nodejs.org/api/crypto.html#crypto_openssl_options
    const crypto = require('crypto');
    config.secureOptions = crypto.constants.SSL_OP_NO_SSLv3 |
                           crypto.constants.SSL_OP_NO_TLSv1 | 
                           crypto.constants.SSL_OP_NO_TLSv1_1;
} catch (err) {
    console.log("Could not configure NodeJS to avoid unsecure SSL/TLS protocols: " + err)
}

// SSL ciphersuit

// When choosing a cipher, use the server's preferences instead of the client 
// preferences. When not set, the SSL server will always follow the clients 
// preferences. More info at: 
// https://www.openssl.org/docs/man1.0.2/ssl/SSL_CTX_set_options.html
config.honorCipherOrder = true;
// Modify default ciphersuit. More info: 
// https://nodejs.org/api/tls.html#tls_modifying_the_default_tls_cipher_suite
config.ciphers =  "";

module.exports = config;
