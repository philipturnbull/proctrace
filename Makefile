all: proctrace

proctrace: main.c
	gcc -Werror -Wall -std=c99 -o proctrace main.c -lcap

clean:
	rm proctrace
