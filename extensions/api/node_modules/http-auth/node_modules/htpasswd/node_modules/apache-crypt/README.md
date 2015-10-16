# apache-crypt
[Node.js](http://nodejs.org/) package for Apache style password encryption using crypt(3).

[![Build Status](https://api.travis-ci.org/gevorg/apache-crypt.png)](https://travis-ci.org/gevorg/apache-crypt)
[![Dependency Status](https://david-dm.org/gevorg/apache-crypt.png)](https://david-dm.org/gevorg/apache-crypt)

## Installation

Via git (or downloaded tarball):

```bash
$ git clone git://github.com/gevorg/apache-crypt.git
```
Via [npm](http://npmjs.org/):

```bash
$ npm install apache-crypt
```

## Usage

```javascript
var crypt = require("apache-crypt");

// Encrypting password using auto-generated 2 char salt.
var encryptedPassword = crypt("mypass");

// Should print true.
console.log(crypt("mypass", encryptedPassword) == encryptedPassword);
// Should print false.
console.log(crypt("notmypass", encryptedPassword) == encryptedPassword);
```

## Running tests

It uses [nodeunit](https://github.com/caolan/nodeunit/), so just run following command in package directory:

```bash
$ npm test
```

## Issues

You can find list of issues using **[this link](http://github.com/gevorg/apache-crypt/issues)**.

## Requirements

 - **[Node.js](http://nodejs.org)** - Event-driven I/O server-side JavaScript       environment based on V8.
 - **[npm](http://npmjs.org)** - Package manager. Installs, publishes and manages   node programs.
 - **[node-gyp](https://github.com/TooTallNate/node-gyp)** - Node.js native addon build tool.

## Development dependencies

 - **[nodeunit](https://github.com/caolan/nodeunit/)** - Easy unit testing in node.js and the browser, based on the assert module.

## License

The MIT License (MIT)

Copyright (c) 2014 Gevorg Harutyunyan

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
