# Author: Dominik Pop
# Login: xpopdo00
# Date: 12.10.2022
# ISA projekt #1

CC=gcc
CFLAGS=-std=gnu99 -Wall
LIBRARIES=-lpcap
FILES= *.c *.h
NAME=flow
LOGIN=xpopdo00

$(NAME): $(FILES)
		$(CC) $(CFLAGS) -o $@ $(FILES) $(LIBRARIES)

clean:
	rm -f *.o $(NAME)

run:
	sudo ./$(NAME)

zip:
	zip $(LOGIN).zip  $(FILES) Makefile flow.1 manual.pdf
