LLC	:	analizador.o  Dibujar.o
		gcc -o LLC  analizador.o Dibujar.o

analizador.o	:	analizador.c tramas.h
			gcc -c analizador.c

		
Dibujar.o	:	Dibujar.c Dibujar.h
			gcc -c Dibujar.c
clean	:
	rm LLC \
	analizador.o Dibujar.o
