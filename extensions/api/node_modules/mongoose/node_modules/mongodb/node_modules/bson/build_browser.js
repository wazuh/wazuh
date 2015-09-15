require('one');

one('./package.json')
  .tie('bson', BSON)
  // .exclude('buffer')
  .tie('buffer', {})
  .save('./browser_build/bson.js')