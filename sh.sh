pdflatex --shell-escape NewFullTimePadPaper.tex
bibtex NewFullTimePadPaper
pdflatex --shell-escape NewFullTimePadPaper.tex
pdflatex --shell-escape NewFullTimePadPaper.tex
evince NewFullTimePadPaper.pdf
