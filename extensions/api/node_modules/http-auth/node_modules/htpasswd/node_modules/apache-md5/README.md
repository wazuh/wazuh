# apache-md5
[Node.js](http://nodejs.org/) package for Apache style password encryption using md5..

[![Build Status](https://api.travis-ci.org/gevorg/apache-md5.png)](https://travis-ci.org/gevorg/apache-md5)
[![Dependency Status](https://david-dm.org/gevorg/apache-md5.png)](https://david-dm.org/gevorg/apache-md5)

## Installation

Via git (or downloaded tarball):

```bash
$ git clone git://github.com/gevorg/apache-md5.git
```
Via [npm](http://npmjs.org/):

```bash
$ npm install apache-md5
```

## Usage

```javascript
var md5 = require("apache-md5");

var encryptedPassword = md5("mypass"); // Encrypting password using apache's md5 algorithm.

console.log(md5("mypass", encryptedPassword) == encryptedPassword); // Should print true.
console.log(md5("notmypass", encryptedPassword) == encryptedPassword); // Should print false.
...
```

## Running tests

It uses [nodeunit](https://github.com/caolan/nodeunit/), so just run following command in package directory:

```bash
$ npm test
```

## Issues

You can find list of issues using **[this link](http://github.com/gevorg/apache-md5/issues)**.

## Requirements

 - **[Node.js](http://nodejs.org)** - Event-driven I/O server-side JavaScript       environment based on V8.
 - **[npm](http://npmjs.org)** - Package manager. Installs, publishes and manages   node programs.

## Development dependencies

 - **[nodeunit](https://github.com/caolan/nodeunit/)** - Easy unit testing in node.js and the browser, based on the assert module.

## License

The MIT License (MIT)

Copyright (c) 2013 Gevorg Harutyunyan

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
