TARGETS = launcher sandbox.so

.PHONY: all
all: $(TARGETS)

sandbox.so: sandbox.cc
	$(CXX) -o $@ $(CFLAGS) -shared -ldl -fPIC $^

.PHONY: clean
clean:
	rm -f $(TARGETS)
