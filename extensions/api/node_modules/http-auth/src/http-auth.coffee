# HTTP integration.
require './server/http'

# HTTPS integration.
require './server/https'

# Only if http-proxy is available.
if (require('./auth/utils').isAvailable('http-proxy'))
  # Proxy integration.
	require('./server/proxy')

# Exporting.
module.exports = {
  basic: (options, checker) -> require('./auth/basic')(options, checker)
  digest: (options, checker) -> require('./auth/digest')(options, checker)
  connect: (authentication) -> require('./server/connect')(authentication)
}
