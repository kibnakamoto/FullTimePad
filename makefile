CXX = g++
CXXFLAGS = -std=c++20 -Wall -pedantic -Wextra -O4
EXEC = fulltimepad 
OBJS = fulltimepad.o
PDF_DOC_FILES = FullTimePad.pdf FullTimePad.toc FullTimePad.aux

all: ${OBJS}
	${CXX} ${CXXFLAGS} ${OBJS} -o ${EXEC}

debug: ${OBJS}
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

pdf_clean:
	rm -rf ${PDF_DOC_FILES}


.PHONY: clean
clean:
	rm -rf ${EXEC} ${OBJS}
