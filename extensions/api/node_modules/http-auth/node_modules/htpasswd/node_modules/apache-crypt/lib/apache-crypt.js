// Import crypt lib.
var lcrypt = require('./libcrypt');

// Salt generation method.
function getSalt() {
    var saltChars = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    return saltChars[ parseInt(Math.random() * 64) ] + saltChars[ parseInt(Math.random() * 64) ];
}

// Exporting function.
module.exports = function(password, salt) {
    return salt ? lcrypt.crypt(password, salt) : lcrypt.crypt(password, getSalt());
};
