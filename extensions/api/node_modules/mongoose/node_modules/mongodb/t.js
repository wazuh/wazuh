var mongodb = require('./lib/mongodb');                                               

var mongoserver = new mongodb.Server('localhost', 27017, {});                   
var db_conn = new mongodb.Db('test1', mongoserver, { w : 1 });                  

db_conn.on('open', function () {                                                
  console.log("this is an open event");                                         
});                                                                             

db_conn.on('close', function () {                                               
  console.log("this is a close event");                                         
});                                                                             

db_conn.on('reconnect', function () {
  console.log("this is a reconnect event");                                         
});                                                                             

db_conn.open(function (err) {                                                   
  if (err) throw err;                                                           

  var col = db_conn.collection('test');                                         

  var count = 0;                                                                
  // Run a simple 'find' query every second                                     
  setInterval(function() {                                                      
    col.findOne(function(err, item) {  
      if (err) {                                                                
        return console.log("mongodb query not ok %d", count)                    
      }                                                                         
      console.log("mongodb query ok %d", count);                                
      count++;                                                                  
    })                                                                          
    if (count == 40) {                                                          
      db_conn.close();                                                          
    }                                                                           
  }, 1000)                                                                      
  console.log('hi');                                                            
});

// var MongoClient = require('./lib/mongodb').MongoClient
// 	, Server = require('./lib/mongodb').Server
//   , ReplSet = require('./lib/mongodb').ReplSet
// 	, Db = require('./lib/mongodb').Db;
// var format = require('util').format;

// var host = process.env['MONGO_NODE_DRIVER_HOST'] || 'localhost'; 
// var port = process.env['MONGO_NODE_DRIVER_PORT'] || 27017;
// var url = format("mongodb://%s:%s,%s:%s,%s:%s/node-mongo-examples"
//         , host, port, host, 27018, host, 27019);
// var url = "mongodb://localhost:27017/node-mongo-examples"
// // console.dir(url)

// // MongoClient.connect(url, function(err, db) {
// // new Db("node-mongo-examples", new Server("localhost", 27017), {w:1}).open(function(err, db) {
// var replSet = new ReplSet([new Server("localhost", 31000)
//   , new Server("localhost", 31001)
//   , new Server("localhost", 31002)])
// new Db("node-mongo-examples", replSet, {safe:true}).open(function(err, db) {
//   if(err) throw err;
//   console.log("=========================== 0")
//   db.close();
// });

//   // console.log("------------------------- 0")

//   // db.on('error', function(err, db) {
//   //  console.log("---------------------- GOT ERROR")
//   //  console.dir(err)
//   //   db.close(function() {
//   //    console.log("----------------- error")
//   //     process.exit(1);
//   //   })
//   // });
//    //  // throw new Error("3")

//   // console.log('connected');

//   // db.collection('t').findOne(function(err, result) {
//   //  console.log("33333")
//    //  throw new Error("3")
//   // })
    
//   // thisMethodDoesNotExists('foo', 'bar', 123);

// process.on("uncaughtException", function(err) {
// 	console.log("######################")
// })

// // var now;
// // var obj, i;
// // var count = 10000000;
// // var key = 'key';
 
// // obj = {};
// // now = Date.now();
// // for (i = 0; i < count; i++) {
// // obj[key] = 1;
// // obj[key] = null;
// // }
// // console.log('null assignment(`obj[key] = null`):\n %d ms', Date.now() - now);
 
// // obj = {};
// // now = Date.now();
// // for (i = 0; i < count; i++) {
// // obj[key] = 1;
// // delete obj[key];
// // }
// // console.log('deleting property(`delete obj[key]`):\n %d ms', Date.now() - now);

// // // var mongodb = require('./lib/mongodb');

// // // // var url = 'mongodb://user:pass@host1,host2,host3/db';
// // // var url = 'mongodb://127.0.0.1:31000,192.168.2.173:31001,127.0.0.1:31002/test';
// // // var options = {db: {safe: true}, server: {auto_reconnect: true}};

// // // mongodb.connect(url, options, function (err, db) {
// // //   if (err) {
// // //     console.log(err);
// // //     process.exit(1);
// // //   }

// // //   db.collection('test', function (err, c) {
// // //     if (err) {
// // //       console.log(err);
// // //       process.exit(2);
// // //     }

// // //     var successCount = 0;
// // //     var errCount = 0;
// // //     var lastErr = null;
// // //     setInterval(function () {
// // //       c.find({}).limit(100).toArray(function (err, results) {
// // //         if (err) {
// // //           lastErr = err;
// // //           errCount++;
// // //         } else {
// // //           successCount++;
// // //         }
// // //       });
// // //     }, 100);

// // //     setInterval(function () {
// // //       console.log("STATUS", successCount, errCount);
// // //     }, 1000);

// // //   });
// // // });