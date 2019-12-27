CXXFLAGS += -std=c++11 -g -Wall
webserver: TU = main.cc
path_test: LDLIBS += -lgtest -lgtest_main
path_test: TU = path_test.cc

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
