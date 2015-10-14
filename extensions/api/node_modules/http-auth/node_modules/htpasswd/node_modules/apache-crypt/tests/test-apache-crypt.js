// Apache crypt.
var crypt = require('../lib/apache-crypt');

module.exports = {
    // Test for valid password.
    testValidPassword: function(test) {
        var crypted = crypt("validPass", "B5xBYM2HbnPqI");

        test.equal(crypted, "B5xBYM2HbnPqI", "Wrong password!");
        test.done();
    },
    // Test for invalid password.
    testInValidPassword: function(test) {
        var crypted = crypt("invalidPass", "B5xBYM2HbnPqI");

        test.notEqual(crypted, "B5xBYM2HbnPqI", "Wrong password!");
        test.done();
    }
};