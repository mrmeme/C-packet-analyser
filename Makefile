all: analyser clean

CC = gcc -ggdb -Wall

C_BINS = analyser.c

analyser:	$(C_BINS)
	$(CC) -o $@ $(C_BINS) -lpcap

clean: 
	rm -rf *.o