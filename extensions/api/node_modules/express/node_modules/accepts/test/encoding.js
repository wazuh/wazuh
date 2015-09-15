
function accepts(encoding) {
  return require('../')({
    headers: {
      'accept-encoding': encoding || ''
    }
  })
}

describe('accepts.encodings()', function(){
  describe('with no arguments', function(){
    describe('when Accept-Encoding is populated', function(){
      it('should return accepted types', function(){
        var accept = accepts('gzip, compress;q=0.2');
        accept.encodings().should.eql(['gzip', 'compress', 'identity']);
        accept.encodings('gzip', 'compress').should.equal('gzip');
      })
    })

    describe('when Accept-Encoding is not populated', function(){
      it('should return identity', function(){
        var accept = accepts();
        accept.encodings().should.eql(['identity']);
        accept.encodings('gzip', 'deflate').should.equal('identity');
      })
    })
  })

  describe('with multiple arguments', function(){
    it('should return the best fit', function(){
      var accept = accepts('gzip, compress;q=0.2');
      accept.encodings('compress', 'gzip').should.eql('gzip');
      accept.encodings('gzip', 'compress').should.eql('gzip');
    })
  })

  describe('with an array', function(){
    it('should return the best fit', function(){
      var accept = accepts('gzip, compress;q=0.2');
      accept.encodings(['compress', 'gzip']).should.eql('gzip');
    })
  })
})