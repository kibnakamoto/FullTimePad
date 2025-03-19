CXX = g++
EXEC_BEST = best_permutation
EXEC_SIG = significant_perm_byte
EXEC_REV = reverse
EXEC_COL = collision
EXEC_BEN = benchmark
EXEC_REP = repetition
OBJ_BEST = best_permutation.o
OBJ_REV = reverse.o
OBJ_SIG = significant_perm_byte.o
OBJ_COL = collision.o
OBJ_BEN = benchmark.o
OBJ_REP = repetition.o

# fulltimepad object file used in collision.cpp
OBJ_FULL = ../fulltimepad.o

# if debug mode
ifeq ($(MAKECMDGOALS), debug)
	CXXFLAGS = -std=c++20 -Wall -pedantic -Wextra -g
else
	CXXFLAGS = -std=c++20 -Wall -pedantic -Wextra -O4
endif



all: ${OBJ_BEST} ${OBJ_SIG} ${OBJ_REV} ${OBJ_COL} ${OBJ_BEN} ${OBJ_FULL} ${OBJ_REP}
	${MAKE} -C ../ # fulltimpad

	${CXX} ${CXXFLAGS} ${OBJ_SIG} -o ${EXEC_SIG} ${OBJ_FULL}
	${CXX} ${CXXFLAGS} ${OBJ_BEST} -o ${EXEC_BEST}
	${CXX} ${CXXFLAGS} ${OBJ_REV} -o ${EXEC_REV} ${OBJ_FULL}
	${CXX} ${CXXFLAGS} ${OBJ_COL} -o ${EXEC_COL} ${OBJ_FULL}
	${CXX} ${CXXFLAGS} ${OBJ_BEN} -o ${EXEC_BEN} ${OBJ_FULL}
	${CXX} ${CXXFLAGS} ${OBJ_REP} -o ${EXEC_REP} ${OBJ_FULL}

debug: ${OBJ_BEST} ${OBJ_SIG} ${OBJ_REV} ${OBJ_COL} ${OBJ_BEN} ${OBJ_FULL} ${OBJ_REP}
	${MAKE} -C ../ # fulltimpad

	${CXX} ${CXXFLAGS} -g ${OBJ_BEST} -o ${EXEC_BEST}
	${CXX} ${CXXFLAGS} -g ${OBJ_SIG} -o ${EXEC_SIG} ${OBJ_FULL}
	${CXX} ${CXXFLAGS} -g ${OBJ_REV} -o ${EXEC_REV} ${OBJ_FULL}
	${CXX} ${CXXFLAGS} -g ${OBJ_COL} -o ${EXEC_COL} ${OBJ_FULL}
	${CXX} ${CXXFLAGS} -g ${OBJ_BEN} -o ${EXEC_BEN} ${OBJ_FULL}
	${CXX} ${CXXFLAGS} -g ${OBJ_REP} -o ${EXEC_REP} ${OBJ_FULL}

.PHONY: clean
clean:
	rm -rf ${EXEC_REP} ${EXEC_BEN} ${EXEC_COL} ${EXEC_REV} ${EXEC_SIG} ${EXEC_BEST} ${OBJ_BEST} ${OBJ_SIG} ${OBJ_REV} ${OBJ_COL} ${OBJ_BEN}  ${OBJ_REP}
