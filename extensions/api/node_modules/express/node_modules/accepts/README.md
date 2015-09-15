# Accepts [![Build Status](https://travis-ci.org/expressjs/accepts.png)](https://travis-ci.org/expressjs/accepts)

Higher level content negotation based on [negotiator](https://github.com/federomero/negotiator). Extracted from [koa](https://github.com/koajs/koa) for general use.

In addition to negotatior, it allows:

- Allows types as an array or arguments list, ie `(['text/html', 'application/json'])` as well as `('text/html', 'application/json')`.
- Allows type shorthands such as `json`.
- Returns `false` when no types match
- Treats non-existent headers as `*`

## API

### var accept = new Accepts(req)

```js
var accepts = require('accepts')

http.createServer(function (req, res) {
  var accept = accepts(req)
})
```

### accept\[property\]\(\)

Returns all the explicitly accepted content property as an array in descending priority.

- `accept.types()`
- `accept.encodings()`
- `accept.charsets()`
- `accept.languages()`

They are also aliased in singular form such as `accept.type()`. `accept.languages()` is also aliased as `accept.langs()`, etc.

Note: you should almost never do this in a real app as it defeats the purpose of content negotiation.

Example:

```js
// in Google Chrome
var encodings = accept.encodings() // -> ['sdch', 'gzip', 'deflate']
```

Since you probably don't support `sdch`, you should just supply the encodings you support:

```js
var encoding = accept.encodings('gzip', 'deflate') // -> 'gzip', probably
```

### accept\[property\]\(values, ...\)

You can either have `values` be an array or have an argument list of values.

If the client does not accept any `values`, `false` will be returned.
If the client accepts any `values`, a filtered list of accepted `values` will be return in descending priority.

For `accept.types()`, shorthand mime types are allowed.

Example:

```js
// req.headers.accept = 'application/json'

accept.types('json') // -> 'json'
accept.types('html', 'json') // -> 'json'
accept.types('html') // -> false

// req.headers.accept = ''
// which is equivalent to `*`

accept.types() // -> [], no explicit types
accept.types('text/html', 'text/json') // -> 'text/html', since it was first
```

## License

The MIT License (MIT)

Copyright (c) 2013 Jonathan Ong me@jongleberry.com

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.