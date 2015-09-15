#regexp-clone
==============

Clones RegExps with flag preservation

```js
var regexpClone = require('regexp-clone');

var a = /somethin/g;
console.log(a.global); // true

var b = regexpClone(a);
console.log(b.global); // true
```

## License

[MIT](https://github.com/aheckmann/regexp-clone/blob/master/LICENSE)
