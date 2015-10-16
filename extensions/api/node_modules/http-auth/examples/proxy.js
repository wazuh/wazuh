// HTTP module.
var http = require('http');

// HTTP proxy module.
var httpProxy = require('http-proxy');

// Authentication module.
var auth = require('../gensrc/http-auth');
var basic = auth.basic({
	realm: "Simon Area.",
	file: __dirname + "/../data/users.htpasswd" // gevorg:gpass, Sarah:testpass ...
});

// Create your proxy server.
httpProxy.createServer(basic, { target: 'http://localhost:1338' }).listen(1337);

// Create your target server.
http.createServer(function (req, res) {
	res.end("Request successfully proxied!");
}).listen(1338);

// Log URL.
console.log("Server running at http://127.0.0.1:1337/");

// You can test proxy authentication using curl.
// $ curl -x 127.0.0.1:1337  127.0.0.1:1337 -U gevorg