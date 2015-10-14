# http-auth
[Node.js](http://nodejs.org/) package for HTTP basic and digest access authentication.

[![Build Status](https://api.travis-ci.org/gevorg/http-auth.png)](https://travis-ci.org/gevorg/http-auth)
[![Dependency Status](https://david-dm.org/gevorg/http-auth.png)](https://david-dm.org/gevorg/http-auth)

## Installation

Via git (or downloaded tarball):

```bash
$ git clone git://github.com/gevorg/http-auth.git
```
Via [npm](http://npmjs.org/):

```bash
$ npm install http-auth
```	

## Basic example
```javascript
// Authentication module.
var auth = require('http-auth');
var basic = auth.basic({
	realm: "Simon Area.",
	file: __dirname + "/../data/users.htpasswd" // gevorg:gpass, Sarah:testpass ...
});

// Creating new HTTP server.
http.createServer(basic, function(req, res) {
	res.end("Welcome to private area - " + req.user + "!");
}).listen(1337);

```
## Custom authentication function
```javascript	
// Authentication module.
var auth = require('http-auth');
var basic = auth.basic({
		realm: "Simon Area."
	}, function (username, password, callback) { // Custom authentication method.
		callback(username === "Tina" && password === "Bullock");
	}
);

// Creating new HTTP server.
http.createServer(basic, function(req, res) {
	res.end("Welcome to private area - " + req.user + "!");
}).listen(1337);
```	
## [express framework](http://expressjs.com/) integration
```javascript
// Authentication module.
var auth = require('http-auth');
var basic = auth.basic({
	realm: "Simon Area.",
	file: __dirname + "/../data/users.htpasswd" // gevorg:gpass, Sarah:testpass ...
});

// Application setup.
var app = express();
app.use(auth.connect(basic));

// Setup route.
app.get('/', function(req, res){
  res.send("Hello from express - " + req.user + "!");
});
```
## [http-proxy](https://github.com/nodejitsu/node-http-proxy/) integration
```javascript
// Authentication module.
var auth = require('http-auth');
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
```
## Configurations

 - `realm` - Authentication realm.
 - `file` - File where user details are stored.
 	- Line format is **{user:pass}** or **{user:passHash}** for basic access. 
 	- Line format is **{user:realm:passHash}** for digest access.
 - `algorithm` - Algorithm that will be used only for **digest** access authentication.
 	- **MD5** by default.
 	- **MD5-sess** can be set.
 - `qop` - Quality of protection that is used only for **digest** access authentication.
 	- **auth** is set by default.
 	- **none** this option is disabling protection.
 - `msg401` - Message for failed authentication 401 page.
 - `msg407` - Message for failed authentication 407 page.
 - `contentType` - Content type for failed authentication page.
 - `skipUser` - Set this to **true**, if you don't want req.user to be filled with authentication info.

## Running tests

It uses [nodeunit](https://github.com/caolan/nodeunit/), so just run following command in package directory:

```bash
$ npm test
```

## Issues

You can find list of issues using **[this link](http://github.com/gevorg/http-auth/issues)**.

## Requirements

 - **[Node.js](http://nodejs.org)** - Event-driven I/O server-side JavaScript environment based on V8.
 - **[npm](http://npmjs.org)** - Package manager. Installs, publishes and manages node programs.

## Utilities

 - **[htpasswd](https://github.com/gevorg/htpasswd/)** - Node.js package for HTTP Basic Authentication password file utility.
 - **[htdigest](https://github.com/gevorg/htdigest/)** - Node.js package for HTTP Digest Authentication password file utility.

## Dependencies

 - **[node-uuid](https://github.com/broofa/node-uuid/)** - Generate RFC4122(v4) UUIDs, and also non-RFC compact ids.
 - **[htpasswd](https://github.com/gevorg/htpasswd/)** - Node.js package for HTTP Basic Authentication password file utility.

## Development dependencies

 - **[coffee-script](http://coffeescript.org/)** - CoffeeScript is a little language that compiles into JavaScript.
 - **[nodeunit](https://github.com/caolan/nodeunit/)** - Easy unit testing in node.js and the browser, based on the assert module.
 - **[express](http://expressjs.com/)** - Sinatra inspired web development framework for node.js -- insanely fast, flexible, and simple.
 - **[http-proxy](https://github.com/nodejitsu/node-http-proxy/)** - A full-featured http proxy for node.js.
 - **[request](https://github.com/mikeal/request/)** - Simplified HTTP request client.

## License

The MIT License (MIT)

Copyright (c) 2015 Gevorg Harutyunyan

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
