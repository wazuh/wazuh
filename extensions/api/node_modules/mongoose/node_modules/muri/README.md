#Meet Muri!

Muri is your friendly neighborhood [MongoDB URI](http://www.mongodb.org/display/DOCS/Connections) parser for Node.js.


###Install

    $ npm install muri

###Use

```js
 var muri = require('muri');
 var o = muri('mongodb://user:pass@local,remote:27018,japan:27019/neatdb?replicaSet=myreplset&journal=true&w=2&wtimeoutMS=50');

 console.log(o);

 { hosts: [ { host: 'local',  port: 27017 },
            { host: 'remote', port: 27018 },
            { host: 'japan',  port: 27019 } ],
   db: 'neatdb',
   options: {
     replicaSet: 'myreplset',
     journal: true,
     w: 2,
     wtimeoutMS: 50
   },
   auth: {
     user: 'user',
     pass: 'pass'
   }
 }
```

### Details

The returned object contains the following properties:

- db: the name of the database. defaults to "admin" if not specified
- auth: if auth is specified, this object will exist `{ user: 'username', pass: 'password' }`
- hosts: array of host/port objects, one for each specified `[{ host: 'local', port: 27107 }, { host: '..', port: port }]`
  - if a port is not specified for a given host, the default port (27017) is used
  - if a unix domain socket is passed, host/port will be undefined and `ipc` will be set to the value specified `[{ ipc: '/tmp/mongodb-27017' }]`
- options: this is a hash of all options specified in the querystring

[LICENSE](https://github.com/aheckmann/muri/blob/master/LICENSE)
