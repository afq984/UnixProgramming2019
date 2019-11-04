TARGETS = launcher sandbox.so
CFLAGS = -g -Wno-attribute-alias
CXXFLAGS = $(CFLAGS)

.PHONY: all
all: $(TARGETS)

sandbox.so: sandbox.cc
	$(CXX) -o $@ $(CXXFLAGS) -shared -ldl -fPIC $^

.PHONY: clean
clean:
	rm -f $(TARGETS)
