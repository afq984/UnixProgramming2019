CFLAGS += -O2 -std=c99
hw1: main.c
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

.PHONY: zip
zip:
	ln -sf . HW1_108062579
	rm -f HW1_108062579.zip
	git ls-files -z | xargs -0 printf 'HW1_108062579/%s\0' | xargs -0 7z a HW1_108062579.zip
	sha256sum HW1_108062579.zip
	unlink HW1_108062579

.PHONY: clean
clean:
	rm -f hw1 HW1_108062579.zip
