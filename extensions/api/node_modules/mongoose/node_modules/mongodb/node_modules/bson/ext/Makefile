NODE = node
name = all
JOBS = 1

all:
	rm -rf build .lock-wscript bson.node
	node-waf configure build
	cp -R ./build/Release/bson.node . || true

all_debug:
	rm -rf build .lock-wscript bson.node
	node-waf --debug configure build
	cp -R ./build/Release/bson.node . || true

clang:
	rm -rf build .lock-wscript bson.node
	CXX=clang node-waf configure build
	cp -R ./build/Release/bson.node . || true

clang_debug:
	rm -rf build .lock-wscript bson.node
	CXX=clang node-waf --debug configure build
	cp -R ./build/Release/bson.node . || true

clean:
	rm -rf build .lock-wscript bson.node

.PHONY: all