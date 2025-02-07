CXX = g++
CXXFLAGS = -std=c++2b -Wall -pedantic -Wextra -O4
EXEC = fulltimepad
OBJS = fulltimepad.o

all: ${OBJS}
	${CXX} ${CXXFLAGS} ${OBJS} -o ${EXEC}

.PHONY: clean
clean:
	rm -rf ${EXEC} ${OBJS}
