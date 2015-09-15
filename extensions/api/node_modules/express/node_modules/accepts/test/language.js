
function accepts(language) {
  return require('../')({
    headers: {
      'accept-language': language || ''
    }
  })
}

describe('accepts.languages()', function(){
  describe('with no arguments', function(){
    describe('when Accept-Language is populated', function(){
      it('should return accepted types', function(){
        var accept = accepts('en;q=0.8, es, pt');
        accept.languages().should.eql(['es', 'pt', 'en']);
      })
    })

    describe('when Accept-Language is not populated', function(){
      it('should return an empty array', function(){
        var accept = accepts();
        accept.languages().should.eql([]);
      })
    })
  })

  describe('with multiple arguments', function(){
    describe('when Accept-Language is populated', function(){
      describe('if any types types match', function(){
        it('should return the best fit', function(){
          var accept = accepts('en;q=0.8, es, pt');
          accept.languages('es', 'en').should.equal('es');
        })
      })

      describe('if no types match', function(){
        it('should return false', function(){
          var accept = accepts('en;q=0.8, es, pt');
          accept.languages('fr', 'au').should.be.false;
        })
      })
    })

    describe('when Accept-Language is not populated', function(){
      it('should return the first type', function(){
        var accept = accepts();
        accept.languages('es', 'en').should.equal('es');
      })
    })
  })

  describe('with an array', function(){
    it('should return the best fit', function(){
      var accept = accepts('en;q=0.8, es, pt');
      accept.languages(['es', 'en']).should.equal('es');
    })
  })
})