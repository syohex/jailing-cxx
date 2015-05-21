CXX ?= g++
CFLAGS ?= -std=c++11 -O2 -Wall
LDFLAGS ?= -lstdc++

all: jailing-cxx

jailing-cxx: src/main.cpp
	$(CXX) $(CFLAGS) -o $@ $<

clean:
	rm -f jailing-c

.PHONY: clean
