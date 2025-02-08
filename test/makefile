CXX = g++
CXXFLAGS = -std=c++2b -Wall -pedantic -Wextra -O4
EXEC = best_permutation
OBJS = best_permutation.o

all: ${OBJS}
	${CXX} ${CXXFLAGS} ${OBJS} -o ${EXEC}

debug: ${OBJS}
	${CXX} ${CXXFLAGS} -g ${OBJS} -o ${EXEC}

.PHONY: clean
clean:
	rm -rf ${EXEC} ${OBJS}
