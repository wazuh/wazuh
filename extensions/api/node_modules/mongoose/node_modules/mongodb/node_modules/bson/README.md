Javascript + C++ BSON parser
============================

This BSON parser is primarily meant for usage with the `mongodb` node.js driver. However thanks to such wonderful tools at `onejs` we are able to package up a BSON parser that will work in the browser aswell. The current build is located in the `browser_build/bson.js` file.

A simple example on how to use it

    <head>
      <script src="https://raw.github.com/mongodb/js-bson/master/browser_build/bson.js">
      </script>
    </head>
    <body onload="start();">
    <script>
      function start() {
        var BSON = bson().BSON;
        var Long = bson().Long;

        var doc = {long: Long.fromNumber(100)}

        // Serialize a document
        var data = BSON.serialize(doc, false, true, false);
        // De serialize it again
        var doc_2 = BSON.deserialize(data);
      }
    </script>
    </body>

  It's got two simple methods to use in your application.

  * BSON.serialize(object, checkKeys, asBuffer, serializeFunctions)
     * @param {Object} object the Javascript object to serialize.
     * @param {Boolean} checkKeys the serializer will check if keys are valid.
     * @param {Boolean} asBuffer return the serialized object as a Buffer object **(ignore)**.
     * @param {Boolean} serializeFunctions serialize the javascript functions **(default:false)**
     * @return {TypedArray/Array} returns a TypedArray or Array depending on what your browser supports
 
  * BSON.deserialize(buffer, options, isArray)
     * Options
       * **evalFunctions** {Boolean, default:false}, evaluate functions in the BSON document scoped to the object deserialized.
       * **cacheFunctions** {Boolean, default:false}, cache evaluated functions for reuse.
       * **cacheFunctionsCrc32** {Boolean, default:false}, use a crc32 code for caching, otherwise use the string of the function.
     * @param {TypedArray/Array} a TypedArray/Array containing the BSON data
     * @param {Object} [options] additional options used for the deserialization.
     * @param {Boolean} [isArray] ignore used for recursive parsing.
     * @return {Object} returns the deserialized Javascript Object.
