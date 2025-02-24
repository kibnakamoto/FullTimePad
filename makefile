CXX = g++
CXXFLAGS = -std=c++20 -Wall -pedantic -Wextra -O4
EXEC = fulltimepad 
OBJS = main.o fulltimepad.o
PDF_DOC_FILES = FullTimePad.pdf FullTimePad.toc FullTimePad.aux FullTimePad.log FullTimePad.out

all: ${EXEC}

${EXEC}: ${OBJS}
	${CXX} ${CXXFLAGS} ${OBJS} -o ${EXEC}

%.o: %.cpp %.h
	${CXX} ${CXXFLAGS} -c $< -o $@

#all: ${OBJS} %.h %.cpp
#	${CXX} ${CXXFLAGS} ${OBJS} -o ${EXEC}

debug: ${OBJS} fulltimepad.h fulltimepad.cpp
	${CXX} ${CXXFLAGS} -g ${OBJS} -o ${EXEC}

test: ${OBJS}
	${MAKE} debug
	${MAKE} -C test

clean_test:
	${MAKE} clean
	${MAKE} -C test clean

pdf:
	pdflatex --shell-escape FullTimePad.tex
	pdflatex --shell-escape FullTimePad.tex
	evince FullTimePad.pdf

clean_pdf:
	rm -rf ${PDF_DOC_FILES}


.PHONY: clean
clean:
	rm -rf ${EXEC} ${OBJS}
