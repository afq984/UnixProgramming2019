TARGETS = launcher sandbox.so

.PHONY: all
all: $(TARGETS)

sandbox.so: sandbox.c
	$(CC) -o $@ $(CFLAGS) -shared $^

.PHONY: clean
clean:
	rm -f $(TARGETS)
