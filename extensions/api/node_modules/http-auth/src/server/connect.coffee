# Exporting connect integration.
module.exports = (authentication) ->
  (req, res, next) -> # Default schema for connect.
    authentication.check req, res, () -> # Authenticated!
      next() # Go forward.
