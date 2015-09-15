
function accepts(type) {
  return require('../')({
    headers: {
      'accept': type || ''
    }
  })
}

describe('accepts.types()', function(){
  describe('with no arguments', function(){
    describe('when Accept is populated', function(){
      it('should return all accepted types', function(){
        var accept = accepts('application/*;q=0.2, image/jpeg;q=0.8, text/html, text/plain');
        accept.types().should.eql(['text/html', 'text/plain', 'image/jpeg', 'application/*']);
      })
    })

    describe('when Accept is not populated', function(){
      it('should return []', function(){
        var accept = accepts();
        accept.types().should.eql([]);
      })
    })
  })

  describe('with no valid types', function(){
    describe('when Accept is populated', function(){
      it('should return false', function(){
        var accept = accepts('application/*;q=0.2, image/jpeg;q=0.8, text/html, text/plain');
        accept.types('image/png', 'image/tiff').should.be.false;
      })
    })

    describe('when Accept is not populated', function(){
      it('should return the first type', function(){
        var accept = accepts();
        accept.types('text/html', 'text/plain', 'image/jpeg', 'application/*').should.equal('text/html');
      })
    })
  })

  describe('when extensions are given', function(){
    it('should convert to mime types', function(){
      var accept = accepts('text/plain, text/html');
      accept.types('html').should.equal('html');
      accept.types('.html').should.equal('.html');
      accept.types('txt').should.equal('txt');
      accept.types('.txt').should.equal('.txt');
      accept.types('png').should.be.false;
    })
  })

  describe('when an array is given', function(){
    it('should return the first match', function(){
      var accept = accepts('text/plain, text/html');
      accept.types(['png', 'text', 'html']).should.equal('text');
      accept.types(['png', 'html']).should.equal('html');
    })
  })

  describe('when multiple arguments are given', function(){
    it('should return the first match', function(){
      var accept = accepts('text/plain, text/html');
      accept.types('png', 'text', 'html').should.equal('text');
      accept.types('png', 'html').should.equal('html');
    })
  })

  describe('when present in Accept as an exact match', function(){
    it('should return the type', function(){
      var accept = accepts('text/plain, text/html');
      accept.types('text/html').should.equal('text/html');
      accept.types('text/plain').should.equal('text/plain');
    })
  })

  describe('when present in Accept as a type match', function(){
    it('should return the type', function(){
      var accept = accepts('application/json, */*');
      accept.types('text/html').should.equal('text/html');
      accept.types('text/plain').should.equal('text/plain');
      accept.types('image/png').should.equal('image/png');
    })
  })

  describe('when present in Accept as a subtype match', function(){
    it('should return the type', function(){
      var accept = accepts('application/json, text/*');
      accept.types('text/html').should.equal('text/html');
      accept.types('text/plain').should.equal('text/plain');
      accept.types('image/png').should.be.false;
    })
  })
})
