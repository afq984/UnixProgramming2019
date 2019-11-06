TARGETS = hw2 launcher sandbox.so
COMMONFLAGS = -g -Wno-attribute-alias
CFLAGS = $(COMMONFLAGS) -std=gnu99
CXXFLAGS = $(COMMONFLAGS) -std=c++17
EXTRATARGETS = test

.PHONY: all
all: $(TARGETS)

sandbox.so: sandbox.cc
	$(CXX) -o $@ $(CXXFLAGS) -shared -ldl -fPIC $^

hw2: launcher
	cp launcher hw2

test: test.cc
	$(CXX) -o $@ $(CXXFLAGS) -lgtest_main -lgtest -ldl $^

test64: test.cc
	$(CXX) -o $@ $(CXXFLAGS) -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 -lgtest_main -lgtest -ldl $^


.PHONY: r
r: test test64 hw2 sandbox.so
	rm -rf testroot
	mkdir testroot
	cd testroot && ../hw2 -p ../sandbox.so ../test
	cd testroot && ../hw2 -p ../sandbox.so ../test64

.PHONY: clean
clean:
	rm -f $(TARGETS)

.PHONY: zip
zip:
	ln -sf . HW2_108062579
	rm -f HW2_108062579.zip
	git ls-files -z | xargs -0 printf 'HW2_108062579/%s\0' | xargs -0 7z a HW2_108062579.zip
	sha256sum HW2_108062579.zip
	unlink HW2_108062579
