#
# Student makefile for DNS resolver lab
# Note: requires a 64-bit x86-64 system 
#
CC = gcc
CFLAGS = -g

all: resolver

resolver: resolver.c
	$(CC) $(CFLAGS) -o resolver resolver.c -lm 

#
# Clean the src dirctory
#
clean:
	rm -f resolver
