CXX = g++
CXXFLAGS = -std=c++20 -Wall -pedantic -Wextra -O4
EXEC_BEST = best_permutation
EXEC_SIG = significant_perm_byte
EXEC_REV = reverse
OBJ_BEST = best_permutation.o
OBJ_REV = reverse.o
OBJ_SIG = significant_perm_byte.o

all: ${OBJ_BEST} ${OBJ_SIG} ${OBJ_REV}
	${CXX} ${CXXFLAGS} ${OBJ_SIG} -o ${EXEC_SIG}
	${CXX} ${CXXFLAGS} ${OBJ_BEST} -o ${EXEC_BEST}
	${CXX} ${CXXFLAGS} ${OBJ_REV} -o ${EXEC_REV}

debug: ${OBJ_BEST} ${OBJ_SIG}
	${CXX} ${CXXFLAGS} -g ${OBJ_BEST} -o ${EXEC_BEST}
	${CXX} ${CXXFLAGS} -g ${OBJ_SIG} -o ${EXEC_SIG}
	${CXX} ${CXXFLAGS} -g ${OBJ_REV} -o ${EXEC_REV}

.PHONY: clean
clean:
	rm -rf ${EXEC_REV} ${EXEC_SIG} ${EXEC_BEST} ${OBJ_BEST} ${OBJ_SIG} ${OBJ_REV} 
