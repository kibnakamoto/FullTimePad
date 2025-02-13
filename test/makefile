CXX = g++
CXXFLAGS = -std=c++2b -Wall -pedantic -Wextra -O4
EXEC_BEST = best_permutation
EXEC_SIG = significant_perm_byte
OBJ_BEST = best_permutation.o
OBJ_SIG = significant_perm_byte.o

all: ${OBJ_BEST} ${OBJ_SIG}
	${CXX} ${CXXFLAGS} ${OBJ_SIG} -o ${EXEC_SIG}
	${CXX} ${CXXFLAGS} ${OBJ_BEST} -o ${EXEC_BEST}

debug: ${OBJ_BEST} ${OBJ_SIG}
	${CXX} ${CXXFLAGS} -g ${OBJ_BEST} -o ${EXEC_BEST}
	${CXX} ${CXXFLAGS} -g ${OBJ_SIG} -o ${EXEC_SIG}

.PHONY: clean
clean:
	rm -rf  ${EXEC_SIG} ${EXEC_BEST} ${OBJ_BEST} ${OBJ_SIG}
