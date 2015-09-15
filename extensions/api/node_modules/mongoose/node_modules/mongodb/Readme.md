Up to date documentation
========================

[Documentation](http://mongodb.github.com/node-mongodb-native/)

Install
=======

To install the most recent release from npm, run:

    npm install mongodb

That may give you a warning telling you that bugs['web'] should be bugs['url'], it would be safe to ignore it (this has been fixed in the development version)

To install the latest from the repository, run::

    npm install path/to/node-mongodb-native

Community
=========
Check out the google group [node-mongodb-native](http://groups.google.com/group/node-mongodb-native) for questions/answers from users of the driver.

Live Examples
============
<a href="https://runnable.com/node-mongodb-native" target="_blank"><img src="https://runnable.com/external/styles/assets/runnablebtn.png" style="width:67px;height:25px;"></a>

Introduction
============

This is a node.js driver for MongoDB. It's a port (or close to a port) of the library for ruby at http://github.com/mongodb/mongo-ruby-driver/.

A simple example of inserting a document.

```javascript
  var MongoClient = require('mongodb').MongoClient
    , format = require('util').format;    

  MongoClient.connect('mongodb://127.0.0.1:27017/test', function(err, db) {
    if(err) throw err;

    var collection = db.collection('test_insert');
    collection.insert({a:2}, function(err, docs) {
      
      collection.count(function(err, count) {
        console.log(format("count = %s", count));
      });

      // Locate all the entries using find
      collection.find().toArray(function(err, results) {
        console.dir(results);
        // Let's close the db
        db.close();
      });      
    });
  })
```

Data types
==========

To store and retrieve the non-JSON MongoDb primitives ([ObjectID](http://www.mongodb.org/display/DOCS/Object+IDs), Long, Binary, [Timestamp](http://www.mongodb.org/display/DOCS/Timestamp+data+type), [DBRef](http://www.mongodb.org/display/DOCS/Database+References#DatabaseReferences-DBRef), Code).

In particular, every document has a unique `_id` which can be almost any type, and by default a 12-byte ObjectID is created. ObjectIDs can be represented as 24-digit hexadecimal strings, but you must convert the string back into an ObjectID before you can use it in the database. For example:

```javascript
  // Get the objectID type
  var ObjectID = require('mongodb').ObjectID;

  var idString = '4e4e1638c85e808431000003';
  collection.findOne({_id: new ObjectID(idString)}, console.log)  // ok
  collection.findOne({_id: idString}, console.log)  // wrong! callback gets undefined
```

Here are the constructors the non-Javascript BSON primitive types:

```javascript
  // Fetch the library
  var mongo = require('mongodb');
  // Create new instances of BSON types
  new mongo.Long(numberString)
  new mongo.ObjectID(hexString)
  new mongo.Timestamp()  // the actual unique number is generated on insert.
  new mongo.DBRef(collectionName, id, dbName)
  new mongo.Binary(buffer)  // takes a string or Buffer
  new mongo.Code(code, [context])
  new mongo.Symbol(string)
  new mongo.MinKey()
  new mongo.MaxKey()
  new mongo.Double(number)	// Force double storage
```

The C/C++ bson parser/serializer
--------------------------------

If you are running a version of this library has the C/C++ parser compiled, to enable the driver to use the C/C++ bson parser pass it the option native_parser:true like below

```javascript
  // using native_parser:
  MongoClient.connect('mongodb://127.0.0.1:27017/test'
    , {db: {native_parser: true}}, function(err, db) {})
```

The C++ parser uses the js objects both for serialization and deserialization.

GitHub information
==================

The source code is available at http://github.com/mongodb/node-mongodb-native.
You can either clone the repository or download a tarball of the latest release.

Once you have the source you can test the driver by running

    $ make test

in the main directory. You will need to have a mongo instance running on localhost for the integration tests to pass.

Examples
========

For examples look in the examples/ directory. You can execute the examples using node.

    $ cd examples
    $ node queries.js

GridStore
=========

The GridStore class allows for storage of binary files in mongoDB using the mongoDB defined files and chunks collection definition.

For more information have a look at [Gridstore](https://github.com/mongodb/node-mongodb-native/blob/master/docs/gridfs.md)

Replicasets
===========
For more information about how to connect to a replicaset have a look at the extensive documentation [Documentation](http://mongodb.github.com/node-mongodb-native/)

Primary Key Factories
---------------------

Defining your own primary key factory allows you to generate your own series of id's
(this could f.ex be to use something like ISBN numbers). The generated the id needs to be a 12 byte long "string".

Simple example below

```javascript
  var MongoClient = require('mongodb').MongoClient
    , format = require('util').format;    

  // Custom factory (need to provide a 12 byte array);
  CustomPKFactory = function() {}
  CustomPKFactory.prototype = new Object();
  CustomPKFactory.createPk = function() {
    return new ObjectID("aaaaaaaaaaaa");
  }

  MongoClient.connect('mongodb://127.0.0.1:27017/test', function(err, db) {
    if(err) throw err;

    db.dropDatabase(function(err, done) {
      
      db.createCollection('test_custom_key', function(err, collection) {
        
        collection.insert({'a':1}, function(err, docs) {
          
          collection.find({'_id':new ObjectID("aaaaaaaaaaaa")}).toArray(function(err, items) {
            console.dir(items);
            // Let's close the db
            db.close();
          });
        });
      });
    });
  });
```

Documentation
=============

If this document doesn't answer your questions, see the source of
[Collection](https://github.com/mongodb/node-mongodb-native/blob/master/lib/mongodb/collection.js)
or [Cursor](https://github.com/mongodb/node-mongodb-native/blob/master/lib/mongodb/cursor.js),
or the documentation at MongoDB for query and update formats.

Find
----

The find method is actually a factory method to create
Cursor objects. A Cursor lazily uses the connection the first time
you call `nextObject`, `each`, or `toArray`.

The basic operation on a cursor is the `nextObject` method
that fetches the next matching document from the database. The convenience
methods `each` and `toArray` call `nextObject` until the cursor is exhausted.

Signatures:

```javascript
  var cursor = collection.find(query, [fields], options);
  cursor.sort(fields).limit(n).skip(m).

  cursor.nextObject(function(err, doc) {});
  cursor.each(function(err, doc) {});
  cursor.toArray(function(err, docs) {});

  cursor.rewind()  // reset the cursor to its initial state.
```

Useful chainable methods of cursor. These can optionally be options of `find` instead of method calls:

  * `.limit(n).skip(m)` to control paging.
  * `.sort(fields)` Order by the given fields. There are several equivalent syntaxes:
  * `.sort({field1: -1, field2: 1})` descending by field1, then ascending by field2.
  * `.sort([['field1', 'desc'], ['field2', 'asc']])` same as above
  * `.sort([['field1', 'desc'], 'field2'])` same as above
  * `.sort('field1')` ascending by field1

Other options of `find`:

* `fields` the fields to fetch (to avoid transferring the entire document)
* `tailable` if true, makes the cursor [tailable](http://www.mongodb.org/display/DOCS/Tailable+Cursors).
* `batchSize` The number of the subset of results to request the database
to return for every request. This should initially be greater than 1 otherwise
the database will automatically close the cursor. The batch size can be set to 1
with `batchSize(n, function(err){})` after performing the initial query to the database.
* `hint` See [Optimization: hint](http://www.mongodb.org/display/DOCS/Optimization#Optimization-Hint).
* `explain` turns this into an explain query. You can also call
`explain()` on any cursor to fetch the explanation.
* `snapshot` prevents documents that are updated while the query is active
from being returned multiple times. See more
[details about query snapshots](http://www.mongodb.org/display/DOCS/How+to+do+Snapshotted+Queries+in+the+Mongo+Database).
* `timeout` if false, asks MongoDb not to time out this cursor after an
inactivity period.


For information on how to create queries, see the
[MongoDB section on querying](http://www.mongodb.org/display/DOCS/Querying).

```javascript
  var MongoClient = require('mongodb').MongoClient
    , format = require('util').format;    

  MongoClient.connect('mongodb://127.0.0.1:27017/test', function(err, db) {
    if(err) throw err;

    var collection = db
      .collection('test')
      .find({})
      .limit(10)
      .toArray(function(err, docs) {
        console.dir(docs);
    });
  });
```

Insert
------

Signature:

```javascript
  collection.insert(docs, options, [callback]);
```

where `docs` can be a single document or an array of documents.

Useful options:

* `safe:true` Should always set if you have a callback.

See also: [MongoDB docs for insert](http://www.mongodb.org/display/DOCS/Inserting).

```javascript
  var MongoClient = require('mongodb').MongoClient
    , format = require('util').format;    

  MongoClient.connect('mongodb://127.0.0.1:27017/test', function(err, db) {
    if(err) throw err;
    
    db.collection('test').insert({hello: 'world'}, {w:1}, function(err, objects) {
      if (err) console.warn(err.message);
      if (err && err.message.indexOf('E11000 ') !== -1) {
        // this _id was already inserted in the database
      }
    });
  });
```

Note that there's no reason to pass a callback to the insert or update commands
unless you use the `safe:true` option. If you don't specify `safe:true`, then
your callback will be called immediately.

Update; update and insert (upsert)
----------------------------------

The update operation will update the first document that matches your query
(or all documents that match if you use `multi:true`).
If `safe:true`, `upsert` is not set, and no documents match, your callback will return 0 documents updated.

See the [MongoDB docs](http://www.mongodb.org/display/DOCS/Updating) for
the modifier (`$inc`, `$set`, `$push`, etc.) formats.

Signature:

```javascript
  collection.update(criteria, objNew, options, [callback]);
```

Useful options:

* `safe:true` Should always set if you have a callback.
* `multi:true` If set, all matching documents are updated, not just the first.
* `upsert:true` Atomically inserts the document if no documents matched.

Example for `update`:

```javascript
  var MongoClient = require('mongodb').MongoClient
    , format = require('util').format;    

  MongoClient.connect('mongodb://127.0.0.1:27017/test', function(err, db) {
    if(err) throw err;

    db.collection('test').update({hi: 'here'}, {$set: {hi: 'there'}}, {w:1}, function(err) {
      if (err) console.warn(err.message);
      else console.log('successfully updated');
    });
  });
```

Find and modify
---------------

`findAndModify` is like `update`, but it also gives the updated document to
your callback. But there are a few key differences between findAndModify and
update:

  1. The signatures differ.
  2. You can only findAndModify a single item, not multiple items.

Signature:

```javascript
    collection.findAndModify(query, sort, update, options, callback)
```

The sort parameter is used to specify which object to operate on, if more than
one document matches. It takes the same format as the cursor sort (see
Connection.find above).

See the
[MongoDB docs for findAndModify](http://www.mongodb.org/display/DOCS/findAndModify+Command)
for more details.

Useful options:

* `remove:true` set to a true to remove the object before returning
* `new:true` set to true if you want to return the modified object rather than the original. Ignored for remove.
* `upsert:true` Atomically inserts the document if no documents matched.

Example for `findAndModify`:

```javascript
  var MongoClient = require('mongodb').MongoClient
    , format = require('util').format;    

  MongoClient.connect('mongodb://127.0.0.1:27017/test', function(err, db) {
    if(err) throw err;
    db.collection('test').findAndModify({hello: 'world'}, [['_id','asc']], {$set: {hi: 'there'}}, {}, function(err, object) {
      if (err) console.warn(err.message);
      else console.dir(object);  // undefined if no matching object exists.
    });
  });
```

Save
----

The `save` method is a shorthand for upsert if the document contains an
`_id`, or an insert if there is no `_id`.

Sponsors
========
Just as Felix Geisendörfer I'm also working on the driver for my own startup and this driver is a big project that also benefits other companies who are using MongoDB.

If your company could benefit from a even better-engineered node.js mongodb driver I would appreciate any type of sponsorship you may be able to provide. All the sponsors will get a lifetime display in this readme, priority support and help on problems and votes on the roadmap decisions for the driver. If you are interested contact me on [christkv AT g m a i l.com](mailto:christkv@gmail.com) for details.

And I'm very thankful for code contributions. If you are interested in working on features please contact me so we can discuss API design and testing.

Release Notes
=============

See HISTORY

Credits
=======

1. [10gen](http://github.com/mongodb/mongo-ruby-driver/)
2. [Google Closure Library](http://code.google.com/closure/library/)
3. [Jonas Raoni Soares Silva](http://jsfromhell.com/classes/binary-parser)

Contributors
============

Aaron Heckmann, Christoph Pojer, Pau Ramon Revilla, Nathan White, Emmerman, Seth LaForge, Boris Filipov, Stefan Schärmeli, Tedde Lundgren, renctan, Sergey Ukustov, Ciaran Jessup, kuno, srimonti, Erik Abele, Pratik Daga, Slobodan Utvic, Kristina Chodorow, Yonathan Randolph, Brian Noguchi, Sam Epstein, James Harrison Fisher, Vladimir Dronnikov, Ben Hockey, Henrik Johansson, Simon Weare, Alex Gorbatchev, Shimon Doodkin, Kyle Mueller, Eran Hammer-Lahav, Marcin Ciszak, François de Metz, Vinay Pulim, nstielau, Adam Wiggins, entrinzikyl, Jeremy Selier, Ian Millington, Public Keating, andrewjstone, Christopher Stott, Corey Jewett, brettkiefer, Rob Holland, Senmiao Liu, heroic, gitfy

License
=======

 Copyright 2009 - 2012 Christian Amor Kvalheim.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

