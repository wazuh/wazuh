// HTTPS module
var https = require('https');

// File system module.
var fs = require('fs');

// Authentication module.
var auth = require('../gensrc/http-auth');
var basic = auth.basic({
	realm: "Simon Area.",
	file: __dirname + "/../data/users.htpasswd" // gevorg:gpass, Sarah:testpass ...
});

// HTTPS server options.
var options = {
	key: fs.readFileSync(__dirname + "/../data/key.pem"),
	cert: fs.readFileSync(__dirname + "/../data/cert.pem")
};

// Starting server.
https.createServer(basic, options, function (req, res) {
	res.end("Welcome to private area - " + req.user + "!");
}).listen(1337);

// Log URL.
console.log("Server running at https://127.0.0.1:1337/");