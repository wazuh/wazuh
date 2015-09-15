function accepts(charset) {
  return require('../')({
    headers: {
      'accept-charset': charset || ''
    }
  })
}

describe('accepts.charsets()', function(){
  describe('with no arguments', function(){
    describe('when Accept-Charset is populated', function(){
      it('should return accepted types', function(){
        var accept = accepts('utf-8, iso-8859-1;q=0.2, utf-7;q=0.5');
        accept.charsets().should.eql(['utf-8', 'utf-7', 'iso-8859-1']);
      })
    })

    describe('when Accept-Charset is not populated', function(){
      it('should return an empty array', function(){
        var accept = accepts();
        accept.charsets().should.eql([]);
      })
    })
  })

  describe('with multiple arguments', function(){
    describe('when Accept-Charset is populated', function(){
      describe('if any types match', function(){
        it('should return the best fit', function(){
          var accept = accepts('utf-8, iso-8859-1;q=0.2, utf-7;q=0.5');
          accept.charsets('utf-7', 'utf-8').should.equal('utf-8');
        })
      })

      describe('if no types match', function(){
        it('should return false', function(){
          var accept = accepts('utf-8, iso-8859-1;q=0.2, utf-7;q=0.5');
          accept.charsets('utf-16').should.be.false;
        })
      })
    })

    describe('when Accept-Charset is not populated', function(){
      it('should return the first type', function(){
        var accept = accepts();
        accept.charsets('utf-7', 'utf-8').should.equal('utf-7');
      })
    })
  })

  describe('with an array', function(){
    it('should return the best fit', function(){
      var accept = accepts('utf-8, iso-8859-1;q=0.2, utf-7;q=0.5');
      accept.charsets(['utf-7', 'utf-8']).should.equal('utf-8');
    })
  })
})