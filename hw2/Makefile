TARGETS = hw2 launcher sandbox.so
COMMONFLAGS = -g -Wno-attribute-alias
CFLAGS = $(COMMONFLAGS) -std=gnu99
CXXFLAGS = $(COMMONFLAGS) -std=c++17

.PHONY: all
all: $(TARGETS)

sandbox.so: sandbox.cc
	$(CXX) -o $@ $(CXXFLAGS) -shared -ldl -fPIC $^

hw2: launcher
	cp launcher hw2

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