TESTS = $(shell find test/ -name '*.test.js')

test:
	@make test-unit && echo "testing promises-A+ implementation ..." && make test-promises-A

test-unit:
	@./node_modules/.bin/mocha $(T) --async-only $(TESTS)

test-promises-A:
	@node test/promises-A.js

.PHONY: test test-unit test-promises-A
