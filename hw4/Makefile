CXXFLAGS += -std=c++11 -g -Wall
webserver: TU = main.cc
path_test: LDLIBS += -lgtest -lgtest_main
path_test: TU = path_test.cc
PKGNAME = HW4_108062579

.PHONY: default
default: webserver

%:
	$(CXX) $(TU) -o $@ $(CXXFLAGS) $(LDLIBS)

webserver: webserver.cc main.cc

path_test: webserver.cc path_test.cc

.PHONY: test
test: path_test
	./path_test

.PHONY: clean
clean:
	rm -f webserver test

.PHONY: zip
zip:
	ln -sf . $(PKGNAME)
	rm -f $(PKGNAME).zip
	git ls-files -z | xargs -0 printf '$(PKGNAME)/%s\0' | xargs -0 7z a $(PKGNAME).zip
	sha256sum $(PKGNAME).zip
	unlink $(PKGNAME)
