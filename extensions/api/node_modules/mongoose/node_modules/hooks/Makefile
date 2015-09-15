test:
	@NODE_ENV=test ./node_modules/expresso/bin/expresso \
		$(TESTFLAGS) \
		./test.js

test-cov:
	@TESTFLAGS=--cov $(MAKE) test

.PHONY: test test-cov
