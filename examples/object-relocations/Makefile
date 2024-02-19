# Variables
CC = gcc
CFLAGS = -Wall -g
TARGET = exe

# Default rule
all: $(TARGET)

$(TARGET): main.o sum.o
	$(CC) $(CFLAGS) -o $(TARGET) main.o sum.o

main.o: main.c sum.h
	$(CC) $(CFLAGS) -c main.c

sum.o: sum.c sum.h
	$(CC) $(CFLAGS) -c sum.c


.PHONY: clean
clean:
	rm -f $(TARGET) sum.o main.o