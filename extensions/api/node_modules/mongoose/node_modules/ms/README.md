
# ms.js

Ever find yourself doing math in your head or writing `1000 * 60 * 60 …`?
Don't want to add obstrusive `Number` prototype extensions to your reusable
/ distributable modules and projects?

`ms` is a tiny utility that you can leverage when your application needs to
accept a number of miliseconds as a parameter.

If a number is supplied to `ms`, it returns it immediately (e.g:
If a string that contains the number is supplied, it returns it immediately as
a number (e.g: it returns `100` for `'100'`).

However, if you pass a string with a number and a valid unit, hte number of
equivalent ms is returned.

```js
ms('1d')      // 86400000
ms('10h')     // 36000000
ms('2h')      // 7200000
ms('1m')      // 60000
ms('5ms')     // 5000
ms('100')     // '100'
ms(100)       // 100
```

## How to use

### Node

```js
require('ms')
```

### Browser

```html
<script src="ms.js"></script>
```

## Credits

(The MIT License)

Copyright (c) 2011 Guillermo Rauch &lt;guillermo@learnboost.com&gt;

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
'Software'), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
