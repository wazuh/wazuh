/**
 * Module dependencies.
 * @ignore
 */
var InsertCommand = require('./commands/insert_command').InsertCommand
  , QueryCommand = require('./commands/query_command').QueryCommand
  , DeleteCommand = require('./commands/delete_command').DeleteCommand
  , UpdateCommand = require('./commands/update_command').UpdateCommand
  , DbCommand = require('./commands/db_command').DbCommand
  , ObjectID = require('bson').ObjectID
  , Code = require('bson').Code
  , Cursor = require('./cursor').Cursor
  , utils = require('./utils');

/**
 * Precompiled regexes
 * @ignore
**/
const eErrorMessages = /No matching object found/;

/**
 * toString helper.
 * @ignore
 */
var toString = Object.prototype.toString;

/**
 * Create a new Collection instance (INTERNAL TYPE)
 *
 * Options
 *  - **readPreference** {String}, the prefered read preference (ReadPreference.PRIMARY, ReadPreference.PRIMARY_PREFERRED, ReadPreference.SECONDARY, ReadPreference.SECONDARY_PREFERRED, ReadPreference.NEAREST).
 *  - **slaveOk** {Boolean, default:false}, Allow reads from secondaries.
 *  - **serializeFunctions** {Boolean, default:false}, serialize functions on the document.
 *  - **raw** {Boolean, default:false}, perform all operations using raw bson objects.
 *  - **pkFactory** {Object}, object overriding the basic ObjectID primary key generation.
 *
 * @class Represents a Collection
 * @param {Object} db db instance.
 * @param {String} collectionName collection name.
 * @param {Object} [pkFactory] alternative primary key factory.
 * @param {Object} [options] additional options for the collection.
 * @return {Object} a collection instance.
 */
function Collection (db, collectionName, pkFactory, options) {
  if(!(this instanceof Collection)) return new Collection(db, collectionName, pkFactory, options);

  checkCollectionName(collectionName);

  this.db = db;
  this.collectionName = collectionName;
  this.internalHint = null;
  this.opts = options != null && ('object' === typeof options) ? options : {};
  this.slaveOk = options == null || options.slaveOk == null ? db.slaveOk : options.slaveOk;
  this.serializeFunctions = options == null || options.serializeFunctions == null ? db.serializeFunctions : options.serializeFunctions;
  this.raw = options == null || options.raw == null ? db.raw : options.raw;

  this.readPreference = options == null || options.readPreference == null ? db.serverConfig.options.readPreference : options.readPreference;
  this.readPreference = this.readPreference == null ? 'primary' : this.readPreference;

  this.pkFactory = pkFactory == null
    ? ObjectID
    : pkFactory;

  var self = this;
}

/**
 * Inserts a single document or a an array of documents into MongoDB.
 *
 * Options
*  - **w**, {Number/String, > -1 || 'majority' || tag name} the write concern for the operation where < 1 is no acknowlegement of write and w >= 1, w = 'majority' or tag acknowledges the write
 *  - **wtimeout**, {Number, 0} set the timeout for waiting for write concern to finish (combines with w option)
 *  - **fsync**, (Boolean, default:false) write waits for fsync before returning
 *  - **journal**, (Boolean, default:false) write waits for journal sync before returning
 *  - **continueOnError/keepGoing** {Boolean, default:false}, keep inserting documents even if one document has an error, *mongodb 1.9.1 >*.
 *  - **serializeFunctions** {Boolean, default:false}, serialize functions on the document.
 *  - **forceServerObjectId** {Boolean, default:false}, let server assign ObjectId instead of the driver
 *  - **checkKeys** {Boolean, default:true}, allows for disabling of document key checking (WARNING OPENS YOU UP TO INJECTION ATTACKS)
 *
 * Deprecated Options
 *  - **safe** {true | {w:n, wtimeout:n} | {fsync:true}, default:false}, executes with a getLastError command returning the results of the command on MongoDB.
 *
 * @param {Array|Object} docs
 * @param {Object} [options] optional options for insert command
 * @param {Function} [callback] optional callback for the function, must be provided when using a writeconcern
 * @return {null}
 * @api public
 */
Collection.prototype.insert = function insert (docs, options, callback) {
  if ('function' === typeof options) callback = options, options = {};
  if(options == null) options = {};
  if(!('function' === typeof callback)) callback = null;
  var self = this;
  insertAll(self, Array.isArray(docs) ? docs : [docs], options, callback);
  return this;
};

/**
 * @ignore
 */
var checkCollectionName = function checkCollectionName (collectionName) {
  if('string' !== typeof collectionName) {
    throw Error("collection name must be a String");
  }

  if(!collectionName || collectionName.indexOf('..') != -1) {
    throw Error("collection names cannot be empty");
  }

  if(collectionName.indexOf('$') != -1 &&
      collectionName.match(/((^\$cmd)|(oplog\.\$main))/) == null) {
    throw Error("collection names must not contain '$'");
  }

  if(collectionName.match(/^\.|\.$/) != null) {
    throw Error("collection names must not start or end with '.'");
  }

  // Validate that we are not passing 0x00 in the colletion name
  if(!!~collectionName.indexOf("\x00")) {
    throw new Error("collection names cannot contain a null character");
  }
};

/**
 * Removes documents specified by `selector` from the db.
 *
 * Options
*  - **w**, {Number/String, > -1 || 'majority' || tag name} the write concern for the operation where < 1 is no acknowlegement of write and w >= 1, w = 'majority' or tag acknowledges the write
 *  - **wtimeout**, {Number, 0} set the timeout for waiting for write concern to finish (combines with w option)
 *  - **fsync**, (Boolean, default:false) write waits for fsync before returning
 *  - **journal**, (Boolean, default:false) write waits for journal sync before returning
 *  - **single** {Boolean, default:false}, removes the first document found.
 *
 * Deprecated Options
 *  - **safe** {true | {w:n, wtimeout:n} | {fsync:true}, default:false}, executes with a getLastError command returning the results of the command on MongoDB.
 *
 * @param {Object} [selector] optional select, no selector is equivalent to removing all documents.
 * @param {Object} [options] additional options during remove.
 * @param {Function} [callback] must be provided if you performing a remove with a writeconcern
 * @return {null}
 * @api public
 */
Collection.prototype.remove = function remove(selector, options, callback) {
  if ('function' === typeof selector) {
    callback = selector;
    selector = options = {};
  } else if ('function' === typeof options) {
    callback = options;
    options = {};
  }

  // Ensure options
  if(options == null) options = {};
  if(!('function' === typeof callback)) callback = null;
  // Ensure we have at least an empty selector
  selector = selector == null ? {} : selector;
  // Set up flags for the command, if we have a single document remove
  var flags = 0 | (options.single ? 1 : 0);

  // DbName
  var dbName = options['dbName'];
  // If no dbname defined use the db one
  if(dbName == null) {
    dbName = this.db.databaseName;
  }

  // Create a delete command
  var deleteCommand = new DeleteCommand(
      this.db
    , dbName + "." + this.collectionName
    , selector
    , flags);

  var self = this;
  var errorOptions = _getWriteConcern(self, options, callback);
  // Execute the command, do not add a callback as it's async
  if(_hasWriteConcern(errorOptions) && typeof callback == 'function') {
    // Insert options
    var commandOptions = {read:false};
    // If we have safe set set async to false
    if(errorOptions == null) commandOptions['async'] = true;
    // Set safe option
    commandOptions['safe'] = true;
    // If we have an error option
    if(typeof errorOptions == 'object') {
      var keys = Object.keys(errorOptions);
      for(var i = 0; i < keys.length; i++) {
        commandOptions[keys[i]] = errorOptions[keys[i]];
      }
    }

    // Execute command with safe options (rolls up both command and safe command into one and executes them on the same connection)
    this.db._executeRemoveCommand(deleteCommand, commandOptions, function (err, error) {
      error = error && error.documents;
      if(!callback) return;

      if(err) {
        callback(err);
      } else if(error[0].err || error[0].errmsg) {
        callback(utils.toError(error[0]));
      } else {
        callback(null, error[0].n);
      }
    });
  } else if(_hasWriteConcern(errorOptions) && callback == null) {
    throw new Error("Cannot use a writeConcern without a provided callback");
  } else {
    var result = this.db._executeRemoveCommand(deleteCommand);
    // If no callback just return
    if (!callback) return;
    // If error return error
    if (result instanceof Error) {
      return callback(result);
    }
    // Otherwise just return
    return callback();
  }
};

/**
 * Renames the collection.
 *
 * Options
 *  - **dropTarget** {Boolean, default:false}, drop the target name collection if it previously exists.
 *
 * @param {String} newName the new name of the collection.
 * @param {Object} [options] returns option results.
 * @param {Function} callback the callback accepting the result
 * @return {null}
 * @api public
 */
Collection.prototype.rename = function rename(newName, options, callback) {
  var self = this;
  if(typeof options == 'function') {
    callback = options;
    options = {}
  }

  // Ensure the new name is valid
  checkCollectionName(newName);
  
  // Execute the command, return the new renamed collection if successful
  self.db._executeQueryCommand(DbCommand.createRenameCollectionCommand(self.db, self.collectionName, newName, options)
    , utils.handleSingleCommandResultReturn(true, false, function(err, result) {
      if(err) return callback(err, null)
      try {
        if(options.new_collection)
          return callback(null, new Collection(self.db, newName, self.db.pkFactory));
        self.collectionName = newName;
        callback(null, self);
      } catch(err) {
        callback(err, null);
      }
    }));
}

/**
 * @ignore
 */
var insertAll = function insertAll (self, docs, options, callback) {
  if('function' === typeof options) callback = options, options = {};
  if(options == null) options = {};
  if(!('function' === typeof callback)) callback = null;

  // Insert options (flags for insert)
  var insertFlags = {};
  // If we have a mongodb version >= 1.9.1 support keepGoing attribute
  if(options['keepGoing'] != null) {
    insertFlags['keepGoing'] = options['keepGoing'];
  }

  // If we have a mongodb version >= 1.9.1 support keepGoing attribute
  if(options['continueOnError'] != null) {
    insertFlags['continueOnError'] = options['continueOnError'];
  }

  // DbName
  var dbName = options['dbName'];
  // If no dbname defined use the db one
  if(dbName == null) {
    dbName = self.db.databaseName;
  }

  // Either use override on the function, or go back to default on either the collection
  // level or db
  if(options['serializeFunctions'] != null) {
    insertFlags['serializeFunctions'] = options['serializeFunctions'];
  } else {
    insertFlags['serializeFunctions'] = self.serializeFunctions;
  }

  // Get checkKeys value
  var checkKeys = typeof options.checkKeys != 'boolean' ? true : options.checkKeys;

  // Pass in options
  var insertCommand = new InsertCommand(
      self.db
    , dbName + "." + self.collectionName, checkKeys, insertFlags);

  // Add the documents and decorate them with id's if they have none
  for(var index = 0, len = docs.length; index < len; ++index) {
    var doc = docs[index];

    // Add id to each document if it's not already defined
    if (!(Buffer.isBuffer(doc))
      && doc['_id'] == null
      && self.db.forceServerObjectId != true
      && options.forceServerObjectId != true) {
        doc['_id'] = self.pkFactory.createPk();
    }

    insertCommand.add(doc);
  }

  // Collect errorOptions
  var errorOptions = _getWriteConcern(self, options, callback);
  // Default command options
  var commandOptions = {};
  // If safe is defined check for error message
  if(_hasWriteConcern(errorOptions) && typeof callback == 'function') {
    // Insert options
    commandOptions['read'] = false;
    // If we have safe set set async to false
    if(errorOptions == null) commandOptions['async'] = true;

    // Set safe option
    commandOptions['safe'] = errorOptions;
    // If we have an error option
    if(typeof errorOptions == 'object') {
      var keys = Object.keys(errorOptions);
      for(var i = 0; i < keys.length; i++) {
        commandOptions[keys[i]] = errorOptions[keys[i]];
      }
    }

    // Execute command with safe options (rolls up both command and safe command into one and executes them on the same connection)
    self.db._executeInsertCommand(insertCommand, commandOptions, function (err, error) {
      error = error && error.documents;
      if(!callback) return;

      if (err) {
        callback(err);
      } else if(error[0].err || error[0].errmsg) {
        callback(utils.toError(error[0]));
      } else {
        callback(null, docs);
      }
    });
  } else if(_hasWriteConcern(errorOptions) && callback == null) {
    throw new Error("Cannot use a writeConcern without a provided callback");
  } else {
    // Execute the call without a write concern
    var result = self.db._executeInsertCommand(insertCommand, commandOptions);
    // If no callback just return
    if(!callback) return;
    // If error return error
    if(result instanceof Error) {
      return callback(result);
    }

    // Otherwise just return
    return callback(null, docs);
  }
};

/**
 * Save a document. Simple full document replacement function. Not recommended for efficiency, use atomic
 * operators and update instead for more efficient operations.
 *
 * Options
*  - **w**, {Number/String, > -1 || 'majority' || tag name} the write concern for the operation where < 1 is no acknowlegement of write and w >= 1, w = 'majority' or tag acknowledges the write
 *  - **wtimeout**, {Number, 0} set the timeout for waiting for write concern to finish (combines with w option)
 *  - **fsync**, (Boolean, default:false) write waits for fsync before returning
 *  - **journal**, (Boolean, default:false) write waits for journal sync before returning
 *
 * Deprecated Options
 *  - **safe** {true | {w:n, wtimeout:n} | {fsync:true}, default:false}, executes with a getLastError command returning the results of the command on MongoDB.
 *
 * @param {Object} [doc] the document to save
 * @param {Object} [options] additional options during remove.
 * @param {Function} [callback] must be provided if you performing a safe save
 * @return {null}
 * @api public
 */
Collection.prototype.save = function save(doc, options, callback) {
  if('function' === typeof options) callback = options, options = null;
  if(options == null) options = {};
  if(!('function' === typeof callback)) callback = null;
  // Throw an error if attempting to perform a bulk operation
  if(Array.isArray(doc)) throw new Error("doc parameter must be a single document");
  // Extract the id, if we have one we need to do a update command
  var id = doc['_id'];
  var commandOptions = _getWriteConcern(this, options, callback);

  if(id) {
    commandOptions.upsert = true;
    this.update({ _id: id }, doc, commandOptions, callback);
  } else {
    this.insert(doc, commandOptions, callback && function (err, docs) {
      if(err) return callback(err, null);

      if(Array.isArray(docs)) {
        callback(err, docs[0]);
      } else {
        callback(err, docs);
      }
    });
  }
};

/**
 * Updates documents.
 *
 * Options
*  - **w**, {Number/String, > -1 || 'majority' || tag name} the write concern for the operation where < 1 is no acknowlegement of write and w >= 1, w = 'majority' or tag acknowledges the write
 *  - **wtimeout**, {Number, 0} set the timeout for waiting for write concern to finish (combines with w option)
 *  - **fsync**, (Boolean, default:false) write waits for fsync before returning
 *  - **journal**, (Boolean, default:false) write waits for journal sync before returning
 *  - **upsert** {Boolean, default:false}, perform an upsert operation.
 *  - **multi** {Boolean, default:false}, update all documents matching the selector.
 *  - **serializeFunctions** {Boolean, default:false}, serialize functions on the document.
 *  - **checkKeys** {Boolean, default:true}, allows for disabling of document key checking (WARNING OPENS YOU UP TO INJECTION ATTACKS)
 *
 * Deprecated Options
 *  - **safe** {true | {w:n, wtimeout:n} | {fsync:true}, default:false}, executes with a getLastError command returning the results of the command on MongoDB.
 *
 * @param {Object} selector the query to select the document/documents to be updated
 * @param {Object} document the fields/vals to be updated, or in the case of an upsert operation, inserted.
 * @param {Object} [options] additional options during update.
 * @param {Function} [callback] must be provided if you performing an update with a writeconcern
 * @return {null}
 * @api public
 */
Collection.prototype.update = function update(selector, document, options, callback) {
  if('function' === typeof options) callback = options, options = null;
  if(options == null) options = {};
  if(!('function' === typeof callback)) callback = null;

  // DbName
  var dbName = options['dbName'];
  // If no dbname defined use the db one
  if(dbName == null) {
    dbName = this.db.databaseName;
  }

  // If we are not providing a selector or document throw
  if(selector == null || typeof selector != 'object') return callback(new Error("selector must be a valid JavaScript object"));
  if(document == null || typeof document != 'object') return callback(new Error("document must be a valid JavaScript object"));

  // Either use override on the function, or go back to default on either the collection
  // level or db
  if(options['serializeFunctions'] != null) {
    options['serializeFunctions'] = options['serializeFunctions'];
  } else {
    options['serializeFunctions'] = this.serializeFunctions;
  }

  // Build the options command
  var updateCommand = new UpdateCommand(
      this.db
    , dbName + "." + this.collectionName
    , selector
    , document
    , options);

  var self = this;
  // Unpack the error options if any
  var errorOptions = _getWriteConcern(this, options, callback);
  // If safe is defined check for error message
  if(_hasWriteConcern(errorOptions) && typeof callback == 'function') {
    // Insert options
    var commandOptions = {read:false};
    // If we have safe set set async to false
    if(errorOptions == null) commandOptions['async'] = true;
    // Set safe option
    commandOptions['safe'] = errorOptions;
    // If we have an error option
    if(typeof errorOptions == 'object') {
      var keys = Object.keys(errorOptions);
      for(var i = 0; i < keys.length; i++) {
        commandOptions[keys[i]] = errorOptions[keys[i]];
      }
    }

    // Execute command with safe options (rolls up both command and safe command into one and executes them on the same connection)
    this.db._executeUpdateCommand(updateCommand, commandOptions, function (err, error) {
      error = error && error.documents;
      if(!callback) return;

      if(err) {
        callback(err);
      } else if(error[0].err || error[0].errmsg) {
        callback(utils.toError(error[0]));
      } else {
        // Perform the callback
        callback(null, error[0].n, error[0]);
      }
    });
  } else if(_hasWriteConcern(errorOptions) && callback == null) {
    throw new Error("Cannot use a writeConcern without a provided callback");
  } else {
    // Execute update
    var result = this.db._executeUpdateCommand(updateCommand);
    // If no callback just return
    if (!callback) return;
    // If error return error
    if (result instanceof Error) {
      return callback(result);
    }
    // Otherwise just return
    return callback();
  }
};

/**
 * The distinct command returns returns a list of distinct values for the given key across a collection.
 *
 * Options
 *  - **readPreference** {String}, the preferred read preference (Server.PRIMARY, Server.PRIMARY_PREFERRED, Server.SECONDARY, Server.SECONDARY_PREFERRED, Server.NEAREST).
 *
 * @param {String} key key to run distinct against.
 * @param {Object} [query] option query to narrow the returned objects.
 * @param {Object} [options] additional options during update.
 * @param {Function} callback this will be called after executing this method. The first parameter will contain the Error object if an error occured, or null otherwise. While the second parameter will contain the results from distinct or null if an error occured.
 * @return {null}
 * @api public
 */
Collection.prototype.distinct = function distinct(key, query, options, callback) {
  var args = Array.prototype.slice.call(arguments, 1);
  callback = args.pop();
  query = args.length ? args.shift() || {} : {};
  options = args.length ? args.shift() || {} : {};

  var mapCommandHash = {
      'distinct': this.collectionName
    , 'query': query
    , 'key': key
  };

  // Set read preference if we set one
  var readPreference = options['readPreference'] ? options['readPreference'] : false;
  // Execute the command
  this.db._executeQueryCommand(DbCommand.createDbSlaveOkCommand(this.db, mapCommandHash)
    , {read:readPreference}
    , utils.handleSingleCommandResultReturn(null, null, function(err, result) {
      if(err) return callback(err, null);
      callback(null, result.values);
    }));
};

/**
 * Count number of matching documents in the db to a query.
 *
 * Options
 *  - **skip** {Number}, The number of documents to skip for the count.
 *  - **limit** {Number}, The limit of documents to count.
 *  - **readPreference** {String}, the preferred read preference (Server.PRIMARY, Server.PRIMARY_PREFERRED, Server.SECONDARY, Server.SECONDARY_PREFERRED, Server.NEAREST).
 *
 * @param {Object} [query] query to filter by before performing count.
 * @param {Object} [options] additional options during count.
 * @param {Function} callback this will be called after executing this method. The first parameter will contain the Error object if an error occured, or null otherwise. While the second parameter will contain the results from the count method or null if an error occured.
 * @return {null}
 * @api public
 */
Collection.prototype.count = function count (query, options, callback) {
  var args = Array.prototype.slice.call(arguments, 0);
  callback = args.pop();
  query = args.length ? args.shift() || {} : {};
  options = args.length ? args.shift() || {} : {};
  var skip = options.skip;
  var limit = options.limit;

  // Final query
  var commandObject = {
      'count': this.collectionName
    , 'query': query
    , 'fields': null
  };

  // Add limit and skip if defined
  if(typeof skip == 'number') commandObject.skip = skip;
  if(typeof limit == 'number') commandObject.limit = limit;

  // Set read preference if we set one
  var readPreference = _getReadConcern(this, options);

  // Execute the command
  this.db._executeQueryCommand(DbCommand.createDbSlaveOkCommand(this.db, commandObject)
    , {read: readPreference}
    , utils.handleSingleCommandResultReturn(null, null, function(err, result) {
      if(err) return callback(err, null);
      if(result == null) return callback(new Error("no result returned for count"), null);
      callback(null, result.n);
    }));
};


/**
 * Drop the collection
 *
 * @param {Function} callback this will be called after executing this method. The first parameter will contain the Error object if an error occured, or null otherwise. While the second parameter will contain the results from the drop method or null if an error occured.
 * @return {null}
 * @api public
 */
Collection.prototype.drop = function drop(callback) {
  this.db.dropCollection(this.collectionName, callback);
};

/**
 * Find and update a document.
 *
 * Options
 *  - **w**, {Number/String, > -1 || 'majority' || tag name} the write concern for the operation where < 1 is no acknowlegement of write and w >= 1, w = 'majority' or tag acknowledges the write
 *  - **wtimeout**, {Number, 0} set the timeout for waiting for write concern to finish (combines with w option)
 *  - **fsync**, (Boolean, default:false) write waits for fsync before returning
 *  - **journal**, (Boolean, default:false) write waits for journal sync before returning
 *  - **remove** {Boolean, default:false}, set to true to remove the object before returning.
 *  - **upsert** {Boolean, default:false}, perform an upsert operation.
 *  - **new** {Boolean, default:false}, set to true if you want to return the modified object rather than the original. Ignored for remove.
 *
 * Deprecated Options
 *  - **safe** {true | {w:n, wtimeout:n} | {fsync:true}, default:false}, executes with a getLastError command returning the results of the command on MongoDB.
 *
 * @param {Object} query query object to locate the object to modify
 * @param {Array}  sort - if multiple docs match, choose the first one in the specified sort order as the object to manipulate
 * @param {Object} doc - the fields/vals to be updated
 * @param {Object} [options] additional options during update.
 * @param {Function} callback this will be called after executing this method. The first parameter will contain the Error object if an error occured, or null otherwise. While the second parameter will contain the results from the findAndModify method or null if an error occured.
 * @return {null}
 * @api public
 */
Collection.prototype.findAndModify = function findAndModify (query, sort, doc, options, callback) {
  var args = Array.prototype.slice.call(arguments, 1);
  callback = args.pop();
  sort = args.length ? args.shift() || [] : [];
  doc = args.length ? args.shift() : null;
  options = args.length ? args.shift() || {} : {};
  var self = this;

  var queryObject = {
      'findandmodify': this.collectionName
    , 'query': query
    , 'sort': utils.formattedOrderClause(sort)
  };

  queryObject.new = options.new ? 1 : 0;
  queryObject.remove = options.remove ? 1 : 0;
  queryObject.upsert = options.upsert ? 1 : 0;

  if (options.fields) {
    queryObject.fields = options.fields;
  }

  if (doc && !options.remove) {
    queryObject.update = doc;
  }

  // Either use override on the function, or go back to default on either the collection
  // level or db
  if(options['serializeFunctions'] != null) {
    options['serializeFunctions'] = options['serializeFunctions'];
  } else {
    options['serializeFunctions'] = this.serializeFunctions;
  }

  // Only run command and rely on getLastError command
  var command = DbCommand.createDbCommand(this.db, queryObject, options)
  // Execute command
  this.db._executeQueryCommand(command
    , {read:false}, utils.handleSingleCommandResultReturn(null, null, function(err, result) {
      if(err) return callback(err, null);
      return callback(null, result.value, result);
    }));
}

/**
 * Find and remove a document
 *
 * Options
*  - **w**, {Number/String, > -1 || 'majority' || tag name} the write concern for the operation where < 1 is no acknowlegement of write and w >= 1, w = 'majority' or tag acknowledges the write
 *  - **wtimeout**, {Number, 0} set the timeout for waiting for write concern to finish (combines with w option)
 *  - **fsync**, (Boolean, default:false) write waits for fsync before returning
 *  - **journal**, (Boolean, default:false) write waits for journal sync before returning
 *
 * Deprecated Options
 *  - **safe** {true | {w:n, wtimeout:n} | {fsync:true}, default:false}, executes with a getLastError command returning the results of the command on MongoDB.
 *
 * @param {Object} query query object to locate the object to modify
 * @param {Array}  sort - if multiple docs match, choose the first one in the specified sort order as the object to manipulate
 * @param {Object} [options] additional options during update.
 * @param {Function} callback this will be called after executing this method. The first parameter will contain the Error object if an error occured, or null otherwise. While the second parameter will contain the results from the findAndRemove method or null if an error occured.
 * @return {null}
 * @api public
 */
Collection.prototype.findAndRemove = function(query, sort, options, callback) {
  var args = Array.prototype.slice.call(arguments, 1);
  callback = args.pop();
  sort = args.length ? args.shift() || [] : [];
  options = args.length ? args.shift() || {} : {};
  // Add the remove option
  options['remove'] = true;
  // Execute the callback
  this.findAndModify(query, sort, null, options, callback);
}

var testForFields = {
    limit: 1, sort: 1, fields:1, skip: 1, hint: 1, explain: 1, snapshot: 1, timeout: 1, tailable: 1, tailableRetryInterval: 1
  , numberOfRetries: 1, awaitdata: 1, exhaust: 1, batchSize: 1, returnKey: 1, maxScan: 1, min: 1, max: 1, showDiskLoc: 1
  , comment: 1, raw: 1, readPreference: 1, partial: 1, read: 1, dbName: 1
};

/**
 * Creates a cursor for a query that can be used to iterate over results from MongoDB
 *
 * Various argument possibilities
 *  - callback?
 *  - selector, callback?,
 *  - selector, fields, callback?
 *  - selector, options, callback?
 *  - selector, fields, options, callback?
 *  - selector, fields, skip, limit, callback?
 *  - selector, fields, skip, limit, timeout, callback?
 *
 * Options
 *  - **limit** {Number, default:0}, sets the limit of documents returned in the query.
 *  - **sort** {Array | Object}, set to sort the documents coming back from the query. Array of indexes, [['a', 1]] etc.
 *  - **fields** {Object}, the fields to return in the query. Object of fields to include or exclude (not both), {'a':1}
 *  - **skip** {Number, default:0}, set to skip N documents ahead in your query (useful for pagination).
 *  - **hint** {Object}, tell the query to use specific indexes in the query. Object of indexes to use, {'_id':1}
 *  - **explain** {Boolean, default:false}, explain the query instead of returning the data.
 *  - **snapshot** {Boolean, default:false}, snapshot query.
 *  - **timeout** {Boolean, default:false}, specify if the cursor can timeout.
 *  - **tailable** {Boolean, default:false}, specify if the cursor is tailable.
 *  - **tailableRetryInterval** {Number, default:100}, specify the miliseconds between getMores on tailable cursor.
 *  - **numberOfRetries** {Number, default:5}, specify the number of times to retry the tailable cursor.
 *  - **awaitdata** {Boolean, default:false} allow the cursor to wait for data, only applicable for tailable cursor.
 *  - **exhaust** {Boolean, default:false} have the server send all the documents at once as getMore packets, not recommended.
 *  - **batchSize** {Number, default:0}, set the batchSize for the getMoreCommand when iterating over the query results.
 *  - **returnKey** {Boolean, default:false}, only return the index key.
 *  - **maxScan** {Number}, Limit the number of items to scan.
 *  - **min** {Number}, Set index bounds.
 *  - **max** {Number}, Set index bounds.
 *  - **showDiskLoc** {Boolean, default:false}, Show disk location of results.
 *  - **comment** {String}, You can put a $comment field on a query to make looking in the profiler logs simpler.
 *  - **raw** {Boolean, default:false}, Return all BSON documents as Raw Buffer documents.
 *  - **readPreference** {String}, the preferred read preference ((Server.PRIMARY, Server.PRIMARY_PREFERRED, Server.SECONDARY, Server.SECONDARY_PREFERRED, Server.NEAREST).
 *  - **numberOfRetries** {Number, default:5}, if using awaidata specifies the number of times to retry on timeout.
 *  - **partial** {Boolean, default:false}, specify if the cursor should return partial results when querying against a sharded system
 *
 * @param {Object|ObjectID} query query object to locate the object to modify
 * @param {Object} [options] additional options during update.
 * @param {Function} callback this will be called after executing this method. The first parameter will contain the Error object if an error occured, or null otherwise. While the second parameter will contain the results from the find method or null if an error occured.
 * @return {Cursor} returns a cursor to the query
 * @api public
 */
Collection.prototype.find = function find () {
  var options
    , args = Array.prototype.slice.call(arguments, 0)
    , has_callback = typeof args[args.length - 1] === 'function'
    , has_weird_callback = typeof args[0] === 'function'
    , callback = has_callback ? args.pop() : (has_weird_callback ? args.shift() : null)
    , len = args.length
    , selector = len >= 1 ? args[0] : {}
    , fields = len >= 2 ? args[1] : undefined;

  if(len === 1 && has_weird_callback) {
    // backwards compat for callback?, options case
    selector = {};
    options = args[0];
  }

  if(len === 2 && !Array.isArray(fields)) {
    var fieldKeys = Object.getOwnPropertyNames(fields);
    var is_option = false;

    for(var i = 0; i < fieldKeys.length; i++) {
      if(testForFields[fieldKeys[i]] != null) {
        is_option = true;
        break;
      }
    }

    if(is_option) {
      options = fields;
      fields = undefined;
    } else {
      options = {};
    }
  } else if(len === 2 && Array.isArray(fields) && !Array.isArray(fields[0])) {
    var newFields = {};
    // Rewrite the array
    for(var i = 0; i < fields.length; i++) {
      newFields[fields[i]] = 1;
    }
    // Set the fields
    fields = newFields;
  }

  if(3 === len) {
    options = args[2];
  }

  // Ensure selector is not null
  selector = selector == null ? {} : selector;
  // Validate correctness off the selector
  var object = selector;
  if(Buffer.isBuffer(object)) {
    var object_size = object[0] | object[1] << 8 | object[2] << 16 | object[3] << 24;
    if(object_size != object.length)  {
      var error = new Error("query selector raw message size does not match message header size [" + object.length + "] != [" + object_size + "]");
      error.name = 'MongoError';
      throw error;
    }
  }

  // Validate correctness of the field selector
  var object = fields;
  if(Buffer.isBuffer(object)) {
    var object_size = object[0] | object[1] << 8 | object[2] << 16 | object[3] << 24;
    if(object_size != object.length)  {
      var error = new Error("query fields raw message size does not match message header size [" + object.length + "] != [" + object_size + "]");
      error.name = 'MongoError';
      throw error;
    }
  }

  // Check special case where we are using an objectId
  if(selector instanceof ObjectID || (selector != null && selector._bsontype == 'ObjectID')) {
    selector = {_id:selector};
  }

  // If it's a serialized fields field we need to just let it through
  // user be warned it better be good
  if(options && options.fields && !(Buffer.isBuffer(options.fields))) {
    fields = {};

    if(Array.isArray(options.fields)) {
      if(!options.fields.length) {
        fields['_id'] = 1;
      } else {
        for (var i = 0, l = options.fields.length; i < l; i++) {
          fields[options.fields[i]] = 1;
        }
      }
    } else {
      fields = options.fields;
    }
  }

  if (!options) options = {};
  options.skip = len > 3 ? args[2] : options.skip ? options.skip : 0;
  options.limit = len > 3 ? args[3] : options.limit ? options.limit : 0;
  options.raw = options.raw != null && typeof options.raw === 'boolean' ? options.raw : this.raw;
  options.hint = options.hint != null ? normalizeHintField(options.hint) : this.internalHint;
  options.timeout = len == 5 ? args[4] : typeof options.timeout === 'undefined' ? undefined : options.timeout;
  // If we have overridden slaveOk otherwise use the default db setting
  options.slaveOk = options.slaveOk != null ? options.slaveOk : this.db.slaveOk;

  // Set option
  var o = options;
  // Support read/readPreference
  if(o["read"] != null) o["readPreference"] = o["read"];
  // Set the read preference
  o.read = o["readPreference"] ? o.readPreference : this.readPreference;
  // Adjust slave ok if read preference is secondary or secondary only
  if(o.read == "secondary" || o.read == "secondaryOnly") options.slaveOk = true;

  // callback for backward compatibility
  if(callback) {
    // TODO refactor Cursor args
    callback(null, new Cursor(this.db, this, selector, fields, o));
  } else {
    return new Cursor(this.db, this, selector, fields, o);
  }
};

/**
 * Normalizes a `hint` argument.
 *
 * @param {String|Object|Array} hint
 * @return {Object}
 * @api private
 */
var normalizeHintField = function normalizeHintField(hint) {
  var finalHint = null;

  if(typeof hint == 'string') {
    finalHint = hint;
  } else if(Array.isArray(hint)) {
    finalHint = {};

    hint.forEach(function(param) {
      finalHint[param] = 1;
    });
  } else if(hint != null && typeof hint == 'object') {
    finalHint = {};
    for (var name in hint) {
      finalHint[name] = hint[name];
    }
  }

  return finalHint;
};

/**
 * Finds a single document based on the query
 *
 * Various argument possibilities
 *  - callback?
 *  - selector, callback?,
 *  - selector, fields, callback?
 *  - selector, options, callback?
 *  - selector, fields, options, callback?
 *  - selector, fields, skip, limit, callback?
 *  - selector, fields, skip, limit, timeout, callback?
 *
 * Options
 *  - **limit** {Number, default:0}, sets the limit of documents returned in the query.
 *  - **sort** {Array | Object}, set to sort the documents coming back from the query. Array of indexes, [['a', 1]] etc.
 *  - **fields** {Object}, the fields to return in the query. Object of fields to include or exclude (not both), {'a':1}
 *  - **skip** {Number, default:0}, set to skip N documents ahead in your query (useful for pagination).
 *  - **hint** {Object}, tell the query to use specific indexes in the query. Object of indexes to use, {'_id':1}
 *  - **explain** {Boolean, default:false}, explain the query instead of returning the data.
 *  - **snapshot** {Boolean, default:false}, snapshot query.
 *  - **timeout** {Boolean, default:false}, specify if the cursor can timeout.
 *  - **tailable** {Boolean, default:false}, specify if the cursor is tailable.
 *  - **batchSize** {Number, default:0}, set the batchSize for the getMoreCommand when iterating over the query results.
 *  - **returnKey** {Boolean, default:false}, only return the index key.
 *  - **maxScan** {Number}, Limit the number of items to scan.
 *  - **min** {Number}, Set index bounds.
 *  - **max** {Number}, Set index bounds.
 *  - **showDiskLoc** {Boolean, default:false}, Show disk location of results.
 *  - **comment** {String}, You can put a $comment field on a query to make looking in the profiler logs simpler.
 *  - **raw** {Boolean, default:false}, Return all BSON documents as Raw Buffer documents.
 *  - **readPreference** {String}, the preferred read preference (Server.PRIMARY, Server.PRIMARY_PREFERRED, Server.SECONDARY, Server.SECONDARY_PREFERRED, Server.NEAREST).
 *  - **partial** {Boolean, default:false}, specify if the cursor should return partial results when querying against a sharded system
 *
 * @param {Object|ObjectID} query query object to locate the object to modify
 * @param {Object} [options] additional options during update.
 * @param {Function} callback this will be called after executing this method. The first parameter will contain the Error object if an error occured, or null otherwise. While the second parameter will contain the results from the findOne method or null if an error occured.
 * @return {Cursor} returns a cursor to the query
 * @api public
 */
Collection.prototype.findOne = function findOne () {
  var self = this;
  var args = Array.prototype.slice.call(arguments, 0);
  var callback = args.pop();
  var cursor = this.find.apply(this, args).limit(-1).batchSize(1);
  // Return the item
  cursor.nextObject(function(err, item) {
    if(err != null) return callback(utils.toError(err), null);
    callback(null, item);
  });
};

/**
 * Creates an index on the collection.
 *
 * Options
*  - **w**, {Number/String, > -1 || 'majority' || tag name} the write concern for the operation where < 1 is no acknowlegement of write and w >= 1, w = 'majority' or tag acknowledges the write
 *  - **wtimeout**, {Number, 0} set the timeout for waiting for write concern to finish (combines with w option)
 *  - **fsync**, (Boolean, default:false) write waits for fsync before returning
 *  - **journal**, (Boolean, default:false) write waits for journal sync before returning
 *  - **unique** {Boolean, default:false}, creates an unique index.
 *  - **sparse** {Boolean, default:false}, creates a sparse index.
 *  - **background** {Boolean, default:false}, creates the index in the background, yielding whenever possible.
 *  - **dropDups** {Boolean, default:false}, a unique index cannot be created on a key that has pre-existing duplicate values. If you would like to create the index anyway, keeping the first document the database indexes and deleting all subsequent documents that have duplicate value
 *  - **min** {Number}, for geospatial indexes set the lower bound for the co-ordinates.
 *  - **max** {Number}, for geospatial indexes set the high bound for the co-ordinates.
 *  - **v** {Number}, specify the format version of the indexes.
 *  - **expireAfterSeconds** {Number}, allows you to expire data on indexes applied to a data (MongoDB 2.2 or higher)
 *  - **name** {String}, override the autogenerated index name (useful if the resulting name is larger than 128 bytes)
 *
 * Deprecated Options
 *  - **safe** {true | {w:n, wtimeout:n} | {fsync:true}, default:false}, executes with a getLastError command returning the results of the command on MongoDB.
 *
 * @param {Object} fieldOrSpec fieldOrSpec that defines the index.
 * @param {Object} [options] additional options during update.
 * @param {Function} callback this will be called after executing this method. The first parameter will contain the Error object if an error occured, or null otherwise. While the second parameter will contain the results from the createIndex method or null if an error occured.
 * @return {null}
 * @api public
 */
Collection.prototype.createIndex = function createIndex (fieldOrSpec, options, callback) {
  // Clean up call
  var args = Array.prototype.slice.call(arguments, 1);
  callback = args.pop();
  options = args.length ? args.shift() || {} : {};
  options = typeof callback === 'function' ? options : callback;
  options = options == null ? {} : options;

  // Collect errorOptions
  var errorOptions = _getWriteConcern(this, options, callback);
  // Execute create index
  this.db.createIndex(this.collectionName, fieldOrSpec, options, callback);
};

/**
 * Ensures that an index exists, if it does not it creates it
 *
 * Options
*  - **w**, {Number/String, > -1 || 'majority' || tag name} the write concern for the operation where < 1 is no acknowlegement of write and w >= 1, w = 'majority' or tag acknowledges the write
 *  - **wtimeout**, {Number, 0} set the timeout for waiting for write concern to finish (combines with w option)
 *  - **fsync**, (Boolean, default:false) write waits for fsync before returning
 *  - **journal**, (Boolean, default:false) write waits for journal sync before returning
 *  - **unique** {Boolean, default:false}, creates an unique index.
 *  - **sparse** {Boolean, default:false}, creates a sparse index.
 *  - **background** {Boolean, default:false}, creates the index in the background, yielding whenever possible.
 *  - **dropDups** {Boolean, default:false}, a unique index cannot be created on a key that has pre-existing duplicate values. If you would like to create the index anyway, keeping the first document the database indexes and deleting all subsequent documents that have duplicate value
 *  - **min** {Number}, for geospatial indexes set the lower bound for the co-ordinates.
 *  - **max** {Number}, for geospatial indexes set the high bound for the co-ordinates.
 *  - **v** {Number}, specify the format version of the indexes.
 *  - **expireAfterSeconds** {Number}, allows you to expire data on indexes applied to a data (MongoDB 2.2 or higher)
 *  - **name** {String}, override the autogenerated index name (useful if the resulting name is larger than 128 bytes)
 *
 * Deprecated Options
 *  - **safe** {true | {w:n, wtimeout:n} | {fsync:true}, default:false}, executes with a getLastError command returning the results of the command on MongoDB.
 *
 * @param {Object} fieldOrSpec fieldOrSpec that defines the index.
 * @param {Object} [options] additional options during update.
 * @param {Function} callback this will be called after executing this method. The first parameter will contain the Error object if an error occured, or null otherwise. While the second parameter will contain the results from the ensureIndex method or null if an error occured.
 * @return {null}
 * @api public
 */
Collection.prototype.ensureIndex = function ensureIndex (fieldOrSpec, options, callback) {
  // Clean up call
  if (typeof callback === 'undefined' && typeof options === 'function') {
    callback = options;
    options = {};
  }

  if (options == null) {
    options = {};
  }

  // Execute create index
  this.db.ensureIndex(this.collectionName, fieldOrSpec, options, callback);
};

/**
 * Retrieves this collections index info.
 *
 * Options
 *  - **full** {Boolean, default:false}, returns the full raw index information.
 *
 * @param {Object} [options] additional options during update.
 * @param {Function} callback this will be called after executing this method. The first parameter will contain the Error object if an error occured, or null otherwise. While the second parameter will contain the results from the indexInformation method or null if an error occured.
 * @return {null}
 * @api public
 */
Collection.prototype.indexInformation = function indexInformation (options, callback) {
  // Unpack calls
  var args = Array.prototype.slice.call(arguments, 0);
  callback = args.pop();
  options = args.length ? args.shift() || {} : {};
  // Call the index information
  this.db.indexInformation(this.collectionName, options, callback);
};

/**
 * Drops an index from this collection.
 *
 * @param {String} name
 * @param {Function} callback this will be called after executing this method. The first parameter will contain the Error object if an error occured, or null otherwise. While the second parameter will contain the results from the dropIndex method or null if an error occured.
 * @return {null}
 * @api public
 */
Collection.prototype.dropIndex = function dropIndex (name, callback) {
  this.db.dropIndex(this.collectionName, name, callback);
};

/**
 * Drops all indexes from this collection.
 *
 * @param {Function} callback this will be called after executing this method. The first parameter will contain the Error object if an error occured, or null otherwise. While the second parameter will contain the results from the dropAllIndexes method or null if an error occured.
 * @return {null}
 * @api public
 */
Collection.prototype.dropAllIndexes = function dropIndexes (callback) {
  this.db.dropIndex(this.collectionName, '*', function (err, result) {
    if(err) return callback(err, false);
    callback(null, true);
  });
}

/**
 * Drops all indexes from this collection.
 *
 * @deprecated
 * @param {Function} callback this will be called after executing this method. The first parameter will contain the Error object if an error occured, or null otherwise. While the second parameter will contain the results from the dropIndexes method or null if an error occured.
 * @return {null}
 * @api private
 */
Collection.prototype.dropIndexes = Collection.prototype.dropAllIndexes;

/**
 * Reindex all indexes on the collection
 * Warning: reIndex is a blocking operation (indexes are rebuilt in the foreground) and will be slow for large collections.
 *
 * @param {Function} callback this will be called after executing this method. The first parameter will contain the Error object if an error occured, or null otherwise. While the second parameter will contain the results from the reIndex method or null if an error occured.
 * @return {null}
 * @api public
**/
Collection.prototype.reIndex = function(callback) {
  this.db.reIndex(this.collectionName, callback);
}

/**
 * Run Map Reduce across a collection. Be aware that the inline option for out will return an array of results not a collection.
 *
 * Options
 *  - **out** {Object}, sets the output target for the map reduce job. *{inline:1} | {replace:'collectionName'} | {merge:'collectionName'} | {reduce:'collectionName'}*
 *  - **query** {Object}, query filter object.
 *  - **sort** {Object}, sorts the input objects using this key. Useful for optimization, like sorting by the emit key for fewer reduces.
 *  - **limit** {Number}, number of objects to return from collection.
 *  - **keeptemp** {Boolean, default:false}, keep temporary data.
 *  - **finalize** {Function | String}, finalize function.
 *  - **scope** {Object}, can pass in variables that can be access from map/reduce/finalize.
 *  - **jsMode** {Boolean, default:false}, it is possible to make the execution stay in JS. Provided in MongoDB > 2.0.X.
 *  - **verbose** {Boolean, default:false}, provide statistics on job execution time.
 *  - **readPreference** {String, only for inline results}, the preferred read preference (Server.PRIMARY, Server.PRIMARY_PREFERRED, Server.SECONDARY, Server.SECONDARY_PREFERRED, Server.NEAREST).
 *
 * @param {Function|String} map the mapping function.
 * @param {Function|String} reduce the reduce function.
 * @param {Objects} [options] options for the map reduce job.
 * @param {Function} callback this will be called after executing this method. The first parameter will contain the Error object if an error occured, or null otherwise. While the second parameter will contain the results from the mapReduce method or null if an error occured.
 * @return {null}
 * @api public
 */
Collection.prototype.mapReduce = function mapReduce (map, reduce, options, callback) {
  if ('function' === typeof options) callback = options, options = {};
  // Out must allways be defined (make sure we don't break weirdly on pre 1.8+ servers)
  if(null == options.out) {
    throw new Error("the out option parameter must be defined, see mongodb docs for possible values");
  }

  if ('function' === typeof map) {
    map = map.toString();
  }

  if ('function' === typeof reduce) {
    reduce = reduce.toString();
  }

  if ('function' === typeof options.finalize) {
    options.finalize = options.finalize.toString();
  }

  var mapCommandHash = {
      mapreduce: this.collectionName
    , map: map
    , reduce: reduce
  };

  // Add any other options passed in
  for (var name in options) {
    if ('scope' == name) {
      mapCommandHash[name] = processScope(options[name]);
    } else {
      mapCommandHash[name] = options[name];
    }
  }

  // Set read preference if we set one
  var readPreference = _getReadConcern(this, options);

  // If we have a read preference and inline is not set as output fail hard
  if((readPreference != false && readPreference != 'primary') 
    && options['out'] && (options['out'].inline != 1 && options['out'] != 'inline')) {
      throw new Error("a readPreference can only be provided when performing an inline mapReduce");
  }

  // self
  var self = this;
  var cmd = DbCommand.createDbCommand(this.db, mapCommandHash);

  this.db._executeQueryCommand(cmd, {read:readPreference}, function (err, result) {
    if(err) return callback(err);
    if(!result || !result.documents || result.documents.length == 0)
      return callback(Error("command failed to return results"), null)

    // Check if we have an error
    if(1 != result.documents[0].ok || result.documents[0].err || result.documents[0].errmsg) {
      return callback(utils.toError(result.documents[0]));
    }

    // Create statistics value
    var stats = {};
    if(result.documents[0].timeMillis) stats['processtime'] = result.documents[0].timeMillis;
    if(result.documents[0].counts) stats['counts'] = result.documents[0].counts;
    if(result.documents[0].timing) stats['timing'] = result.documents[0].timing;

    // invoked with inline?
    if(result.documents[0].results) {
      return callback(null, result.documents[0].results, stats);
    }

    // The returned collection
    var collection = null;

    // If we have an object it's a different db
    if(result.documents[0].result != null && typeof result.documents[0].result == 'object') {
      var doc = result.documents[0].result;
      collection = self.db.db(doc.db).collection(doc.collection);
    } else {
      // Create a collection object that wraps the result collection
      collection = self.db.collection(result.documents[0].result)
    }

    // If we wish for no verbosity
    if(options['verbose'] == null || !options['verbose']) {
      return callback(err, collection);
    }

    // Return stats as third set of values
    callback(err, collection, stats);
  });
};

/**
 * Functions that are passed as scope args must
 * be converted to Code instances.
 * @ignore
 */
function processScope (scope) {
  if (!utils.isObject(scope)) {
    return scope;
  }

  var keys = Object.keys(scope);
  var i = keys.length;
  var key;

  while (i--) {
    key = keys[i];
    if ('function' == typeof scope[key]) {
      scope[key] = new Code(String(scope[key]));
    }
  }

  return scope;
}

/**
 * Group function helper
 * @ignore
 */
var groupFunction = function () {
  var c = db[ns].find(condition);
  var map = new Map();
  var reduce_function = reduce;

  while (c.hasNext()) {
    var obj = c.next();
    var key = {};

    for (var i = 0, len = keys.length; i < len; ++i) {
      var k = keys[i];
      key[k] = obj[k];
    }

    var aggObj = map.get(key);

    if (aggObj == null) {
      var newObj = Object.extend({}, key);
      aggObj = Object.extend(newObj, initial);
      map.put(key, aggObj);
    }

    reduce_function(obj, aggObj);
  }

  return { "result": map.values() };
}.toString();

/**
 * Run a group command across a collection
  *
 * Options
 *  - **readPreference** {String}, the preferred read preference (Server.PRIMARY, Server.PRIMARY_PREFERRED, Server.SECONDARY, Server.SECONDARY_PREFERRED, Server.NEAREST).
 *
 * @param {Object|Array|Function|Code} keys an object, array or function expressing the keys to group by.
 * @param {Object} condition an optional condition that must be true for a row to be considered.
 * @param {Object} initial initial value of the aggregation counter object.
 * @param {Function|Code} reduce the reduce function aggregates (reduces) the objects iterated
 * @param {Function|Code} finalize an optional function to be run on each item in the result set just before the item is returned.
 * @param {Boolean} command specify if you wish to run using the internal group command or using eval, default is true.
 * @param {Object} [options] additional options during update.
 * @param {Function} callback this will be called after executing this method. The first parameter will contain the Error object if an error occured, or null otherwise. While the second parameter will contain the results from the group method or null if an error occured.
 * @return {null}
 * @api public
 */
Collection.prototype.group = function group(keys, condition, initial, reduce, finalize, command, options, callback) {
  var args = Array.prototype.slice.call(arguments, 3);
  callback = args.pop();
  // Fetch all commands
  reduce = args.length ? args.shift() : null;
  finalize = args.length ? args.shift() : null;
  command = args.length ? args.shift() : null;
  options = args.length ? args.shift() || {} : {};

  // Make sure we are backward compatible
  if(!(typeof finalize == 'function')) {
    command = finalize;
    finalize = null;
  }

  if (!Array.isArray(keys) && keys instanceof Object && typeof(keys) !== 'function' && !(keys instanceof Code)) {
    keys = Object.keys(keys);
  }

  if(typeof reduce === 'function') {
    reduce = reduce.toString();
  }

  if(typeof finalize === 'function') {
    finalize = finalize.toString();
  }

  // Set up the command as default
  command = command == null ? true : command;

  // Execute using the command
  if(command) {
    var reduceFunction = reduce instanceof Code
        ? reduce
        : new Code(reduce);

    var selector = {
      group: {
          'ns': this.collectionName
        , '$reduce': reduceFunction
        , 'cond': condition
        , 'initial': initial
        , 'out': "inline"
      }
    };

    // if finalize is defined
    if(finalize != null) selector.group['finalize'] = finalize;
    // Set up group selector
    if ('function' === typeof keys || keys instanceof Code) {
      selector.group.$keyf = keys instanceof Code
        ? keys
        : new Code(keys);
    } else {
      var hash = {};
      keys.forEach(function (key) {
        hash[key] = 1;
      });
      selector.group.key = hash;
    }

    var cmd = DbCommand.createDbSlaveOkCommand(this.db, selector);
    // Set read preference if we set one
    var readPreference = _getReadConcern(this, options);
    // Execute the command
    this.db._executeQueryCommand(cmd
      , {read:readPreference}
      , utils.handleSingleCommandResultReturn(null, null, function(err, result) {
        if(err) return callback(err, null);
        callback(null, result.retval);
      }));
  } else {
    // Create execution scope
    var scope = reduce != null && reduce instanceof Code
      ? reduce.scope
      : {};

    scope.ns = this.collectionName;
    scope.keys = keys;
    scope.condition = condition;
    scope.initial = initial;

    // Pass in the function text to execute within mongodb.
    var groupfn = groupFunction.replace(/ reduce;/, reduce.toString() + ';');

    this.db.eval(new Code(groupfn, scope), function (err, results) {
      if (err) return callback(err, null);
      callback(null, results.result || results);
    });
  }
};

/**
 * Returns the options of the collection.
 *
 * @param {Function} callback this will be called after executing this method. The first parameter will contain the Error object if an error occured, or null otherwise. While the second parameter will contain the results from the options method or null if an error occured.
 * @return {null}
 * @api public
 */
Collection.prototype.options = function options(callback) {
  this.db.collectionsInfo(this.collectionName, function (err, cursor) {
    if (err) return callback(err);
    cursor.nextObject(function (err, document) {
      callback(err, document && document.options || null);
    });
  });
};

/**
 * Returns if the collection is a capped collection
 *
 * @param {Function} callback this will be called after executing this method. The first parameter will contain the Error object if an error occured, or null otherwise. While the second parameter will contain the results from the isCapped method or null if an error occured.
 * @return {null}
 * @api public
 */
Collection.prototype.isCapped = function isCapped(callback) {
  this.options(function(err, document) {
    if(err != null) {
      callback(err);
    } else {
      callback(null, document && document.capped);
    }
  });
};

/**
 * Checks if one or more indexes exist on the collection
 *
 * @param {String|Array} indexNames check if one or more indexes exist on the collection.
 * @param {Function} callback this will be called after executing this method. The first parameter will contain the Error object if an error occured, or null otherwise. While the second parameter will contain the results from the indexExists method or null if an error occured.
 * @return {null}
 * @api public
 */
Collection.prototype.indexExists = function indexExists(indexes, callback) {
 this.indexInformation(function(err, indexInformation) {
   // If we have an error return
   if(err != null) return callback(err, null);
   // Let's check for the index names
   if(Array.isArray(indexes)) {
     for(var i = 0; i < indexes.length; i++) {
       if(indexInformation[indexes[i]] == null) {
         return callback(null, false);
       }
     }

     // All keys found return true
     return callback(null, true);
   } else {
     return callback(null, indexInformation[indexes] != null);
   }
 });
}

/**
 * Execute the geoNear command to search for items in the collection
 *
 * Options
 *  - **num** {Number}, max number of results to return.
 *  - **maxDistance** {Number}, include results up to maxDistance from the point.
 *  - **distanceMultiplier** {Number}, include a value to multiply the distances with allowing for range conversions.
 *  - **query** {Object}, filter the results by a query.
 *  - **spherical** {Boolean, default:false}, perform query using a spherical model.
 *  - **uniqueDocs** {Boolean, default:false}, the closest location in a document to the center of the search region will always be returned MongoDB > 2.X.
 *  - **includeLocs** {Boolean, default:false}, include the location data fields in the top level of the results MongoDB > 2.X.
 *  - **readPreference** {String}, the preferred read preference ((Server.PRIMARY, Server.PRIMARY_PREFERRED, Server.SECONDARY, Server.SECONDARY_PREFERRED, Server.NEAREST).
 *
 * @param {Number} x point to search on the x axis, ensure the indexes are ordered in the same order.
 * @param {Number} y point to search on the y axis, ensure the indexes are ordered in the same order.
 * @param {Objects} [options] options for the map reduce job.
 * @param {Function} callback this will be called after executing this method. The first parameter will contain the Error object if an error occured, or null otherwise. While the second parameter will contain the results from the geoNear method or null if an error occured.
 * @return {null}
 * @api public
 */
Collection.prototype.geoNear = function geoNear(x, y, options, callback) {
  var args = Array.prototype.slice.call(arguments, 2);
  callback = args.pop();
  // Fetch all commands
  options = args.length ? args.shift() || {} : {};

  // Build command object
  var commandObject = {
    geoNear:this.collectionName,
    near: [x, y]
  }

  // Decorate object if any with known properties
  if(options['num'] != null) commandObject['num'] = options['num'];
  if(options['maxDistance'] != null) commandObject['maxDistance'] = options['maxDistance'];
  if(options['distanceMultiplier'] != null) commandObject['distanceMultiplier'] = options['distanceMultiplier'];
  if(options['query'] != null) commandObject['query'] = options['query'];
  if(options['spherical'] != null) commandObject['spherical'] = options['spherical'];
  if(options['uniqueDocs'] != null) commandObject['uniqueDocs'] = options['uniqueDocs'];
  if(options['includeLocs'] != null) commandObject['includeLocs'] = options['includeLocs'];

  // Ensure we have the right read preference inheritance
  options.readPreference = _getReadConcern(this, options);

  // Execute the command
  this.db.command(commandObject, options, function (err, res) {
    if (err) {
      callback(err);
    } else if (res.err || res.errmsg) {
      callback(utils.toError(res));
    } else {
      // should we only be returning res.results here? Not sure if the user
      // should see the other return information
      callback(null, res);
    }
  });
}

/**
 * Execute a geo search using a geo haystack index on a collection.
 *
 * Options
 *  - **maxDistance** {Number}, include results up to maxDistance from the point.
 *  - **search** {Object}, filter the results by a query.
 *  - **limit** {Number}, max number of results to return.
 *  - **readPreference** {String}, the preferred read preference ((Server.PRIMARY, Server.PRIMARY_PREFERRED, Server.SECONDARY, Server.SECONDARY_PREFERRED, Server.NEAREST).
 *
 * @param {Number} x point to search on the x axis, ensure the indexes are ordered in the same order.
 * @param {Number} y point to search on the y axis, ensure the indexes are ordered in the same order.
 * @param {Objects} [options] options for the map reduce job.
 * @param {Function} callback this will be called after executing this method. The first parameter will contain the Error object if an error occured, or null otherwise. While the second parameter will contain the results from the geoHaystackSearch method or null if an error occured.
 * @return {null}
 * @api public
 */
Collection.prototype.geoHaystackSearch = function geoHaystackSearch(x, y, options, callback) {
  var args = Array.prototype.slice.call(arguments, 2);
  callback = args.pop();
  // Fetch all commands
  options = args.length ? args.shift() || {} : {};

  // Build command object
  var commandObject = {
    geoSearch:this.collectionName,
    near: [x, y]
  }

  // Decorate object if any with known properties
  if(options['maxDistance'] != null) commandObject['maxDistance'] = options['maxDistance'];
  if(options['query'] != null) commandObject['search'] = options['query'];
  if(options['search'] != null) commandObject['search'] = options['search'];
  if(options['limit'] != null) commandObject['limit'] = options['limit'];

  // Ensure we have the right read preference inheritance
  options.readPreference = _getReadConcern(this, options);

  // Execute the command
  this.db.command(commandObject, options, function (err, res) {
    if (err) {
      callback(err);
    } else if (res.err || res.errmsg) {
      callback(utils.toError(res));
    } else {
      // should we only be returning res.results here? Not sure if the user
      // should see the other return information
      callback(null, res);
    }
  });
}

/**
 * Retrieve all the indexes on the collection.
 *
 * @param {Function} callback this will be called after executing this method. The first parameter will contain the Error object if an error occured, or null otherwise. While the second parameter will contain the results from the indexes method or null if an error occured.
 * @return {null}
 * @api public
 */
Collection.prototype.indexes = function indexes(callback) {
  // Return all the index information
  this.db.indexInformation(this.collectionName, {full:true}, callback);
}

/**
 * Execute an aggregation framework pipeline against the collection, needs MongoDB >= 2.1
 *
 * Options
 *  - **readPreference** {String}, the preferred read preference ((Server.PRIMARY, Server.PRIMARY_PREFERRED, Server.SECONDARY, Server.SECONDARY_PREFERRED, Server.NEAREST).
 *
 * @param {Array} array containing all the aggregation framework commands for the execution.
 * @param {Object} [options] additional options during update.
 * @param {Function} callback this will be called after executing this method. The first parameter will contain the Error object if an error occured, or null otherwise. While the second parameter will contain the results from the aggregate method or null if an error occured.
 * @return {null}
 * @api public
 */
Collection.prototype.aggregate = function(pipeline, options, callback) {
  // *  - **explain** {Boolean}, return the query plan for the aggregation pipeline instead of the results. 2.3, 2.4
  var args = Array.prototype.slice.call(arguments, 0);
  callback = args.pop();
  var self = this;

  // If we have any of the supported options in the options object
  var opts = args[args.length - 1];
  options = opts.readPreference || opts.explain ? args.pop() : {}

  // Convert operations to an array
  if(!Array.isArray(args[0])) {
    pipeline = [];
    // Push all the operations to the pipeline
    for(var i = 0; i < args.length; i++) pipeline.push(args[i]);
  }

  // Build the command
  var command = { aggregate : this.collectionName, pipeline : pipeline};

  // Ensure we have the right read preference inheritance
  options.readPreference = _getReadConcern(this, options);

  // Execute the command
  this.db.command(command, options, function(err, result) {
    if(err) {
      callback(err);
    } else if(result['err'] || result['errmsg']) {
      callback(utils.toError(result));
    } else if(typeof result == 'object' && result['serverPipeline']) {
      callback(null, result);
    } else {
      callback(null, result.result);
    }
  });
}

/**
 * Get all the collection statistics.
 *
 * Options
 *  - **scale** {Number}, divide the returned sizes by scale value.
 *  - **readPreference** {String}, the preferred read preference ((Server.PRIMARY, Server.PRIMARY_PREFERRED, Server.SECONDARY, Server.SECONDARY_PREFERRED, Server.NEAREST).
 *
 * @param {Objects} [options] options for the stats command.
 * @param {Function} callback this will be called after executing this method. The first parameter will contain the Error object if an error occured, or null otherwise. While the second parameter will contain the results from the stats method or null if an error occured.
 * @return {null}
 * @api public
 */
Collection.prototype.stats = function stats(options, callback) {
  var args = Array.prototype.slice.call(arguments, 0);
  callback = args.pop();
  // Fetch all commands
  options = args.length ? args.shift() || {} : {};

  // Build command object
  var commandObject = {
    collStats:this.collectionName,
  }

  // Check if we have the scale value
  if(options['scale'] != null) commandObject['scale'] = options['scale'];

  // Ensure we have the right read preference inheritance
  options.readPreference = _getReadConcern(this, options);

  // Execute the command
  this.db.command(commandObject, options, callback);
}

/**
 * @ignore
 */
Object.defineProperty(Collection.prototype, "hint", {
    enumerable: true
  , get: function () {
      return this.internalHint;
    }
  , set: function (v) {
      this.internalHint = normalizeHintField(v);
    }
});

var _getReadConcern = function(self, options) {
  if(options.readPreference) return options.readPreference;
  if(self.readPreference) return self.readPreference;
  if(self.db.readPreference) return self.readPreference;
  return 'primary';
}

/**
 * @ignore
 */
var _hasWriteConcern = function(errorOptions) {
  return errorOptions == true
    || errorOptions.w > 0
    || errorOptions.w == 'majority'
    || errorOptions.j == true
    || errorOptions.journal == true
    || errorOptions.fsync == true
}

/**
 * @ignore
 */
var _setWriteConcernHash = function(options) {
  var finalOptions = {};
  if(options.w != null) finalOptions.w = options.w;
  if(options.journal == true) finalOptions.j = options.journal;
  if(options.j == true) finalOptions.j = options.j;
  if(options.fsync == true) finalOptions.fsync = options.fsync;
  if(options.wtimeout != null) finalOptions.wtimeout = options.wtimeout;
  return finalOptions;
}

/**
 * @ignore
 */
var _getWriteConcern = function(self, options, callback) {
  // Final options
  var finalOptions = {w:1};
  // Local options verification
  if(options.w != null || typeof options.j == 'boolean' || typeof options.journal == 'boolean' || typeof options.fsync == 'boolean') {
    finalOptions = _setWriteConcernHash(options);
  } else if(typeof options.safe == "boolean") {
    finalOptions = {w: (options.safe ? 1 : 0)};
  } else if(options.safe != null && typeof options.safe == 'object') {
    finalOptions = _setWriteConcernHash(options.safe);
  } else if(self.opts.w != null || typeof self.opts.j == 'boolean' || typeof self.opts.journal == 'boolean' || typeof self.opts.fsync == 'boolean') {
    finalOptions = _setWriteConcernHash(self.opts);
  } else if(typeof self.opts.safe == "boolean") {
    finalOptions = {w: (self.opts.safe ? 1 : 0)};
  } else if(self.db.safe.w != null || typeof self.db.safe.j == 'boolean' || typeof self.db.safe.journal == 'boolean' || typeof self.db.safe.fsync == 'boolean') {
    finalOptions = _setWriteConcernHash(self.db.safe);
  } else if(self.db.options.w != null || typeof self.db.options.j == 'boolean' || typeof self.db.options.journal == 'boolean' || typeof self.db.options.fsync == 'boolean') {
    finalOptions = _setWriteConcernHash(self.db.options);
  } else if(typeof self.db.safe == "boolean") {
    finalOptions = {w: (self.db.safe ? 1 : 0)};
  }

  // Ensure we don't have an invalid combination of write concerns
  if(finalOptions.w < 1
    && (finalOptions.journal == true || finalOptions.j == true || finalOptions.fsync == true)) throw new Error("No acknowlegement using w < 1 cannot be combined with journal:true or fsync:true");

  // Return the options
  return finalOptions;
}

/**
 * Expose.
 */
exports.Collection = Collection;
