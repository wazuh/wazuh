# htpasswd
[Node.js](http://nodejs.org/) package for HTTP Basic Authentication password file utility.

[![Build Status](https://api.travis-ci.org/gevorg/htpasswd.png)](https://travis-ci.org/gevorg/htpasswd)
[![Dependency Status](https://david-dm.org/gevorg/htpasswd.png)](https://david-dm.org/gevorg/htpasswd)

## Installation

Via git (or downloaded tarball):

```bash
$ git clone git://github.com/gevorg/htpasswd.git
```
Via [npm](http://npmjs.org/):

```bash
$ npm install -g htpasswd
```	
## Usage

```bash
$ htpasswd [-cimpsDv] passwordfile username
$ htpasswd -b[cmpsDv] passwordfile username password

$ htpasswd -n[imps] username
$ htpasswd -nb[mps] username password
```	

## Options

 - `-b` - Use the password from the command line rather than prompting for it. This option should be used with extreme care, since the password is clearly visible on the command line. For script use see the -i option.
 - `-i` - Read the password from stdin without verification (for script usage).
 - `-c` - Create a new file.
 - `-n` - Don't update file; display results on stdout.
 - `-m` - Use MD5 encryption for passwords. This is the default.
 - `-d` - Use crypt() encryption for passwords. This algorithm limits the password length to 8 characters. This algorithm is insecure by today's standards.
 - `-s` - Use SHA encryption for passwords. This algorithm is insecure by today's standards.
 - `-p` - Do not encrypt the password (plaintext).
 - `-D` - Delete the specified user.
 - `-v` - Verify password. Verify that the given password matches the password of the user stored in the specified htpasswd file.

## Running tests

It uses [nodeunit](https://github.com/caolan/nodeunit/), so just run following command in package directory:

```bash
$ npm test
```

## Issues

You can find list of issues using **[this link](http://github.com/gevorg/htpasswd/issues)**.

## Requirements

 - **[Node.js](http://nodejs.org)** - Event-driven I/O server-side JavaScript       environment based on V8.
 - **[npm](http://npmjs.org)** - Package manager. Installs, publishes and manages   node programs.

## Dependencies

 - **[commander](https://github.com/visionmedia/commander.js/)** - node.js command-line interfaces made easy.
 - **[coffee-script](http://coffeescript.org/)** - CoffeeScript is a little language that compiles into JavaScript.
 - **[prompt](https://github.com/flatiron/prompt)** - a beautiful command-line prompt for node.js.
 - **[apache-md5](https://github.com/gevorg/apache-md5)** - Node.js module for Apache style password encryption using md5.
 - **[apache-crypt](https://github.com/gevorg/apache-crypt)** - Node.js module for Apache style password encryption using crypt(3).

## Development dependencies

 - **[nodeunit](https://github.com/caolan/nodeunit/)** - Easy unit testing in node.js and the browser, based on the assert module.

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
