# Variables
CC = gcc
CFLAGS = -Wall -g
TARGET = exe

# Default rule
all: $(TARGET)

$(TARGET): main.c sum.o
	$(CC) $(CFLAGS) -o $(TARGET) main.c sum.o

sum.o: sum.c sum.h
	$(CC) $(CFLAGS) -c sum.c


.PHONY: clean
clean:
	rm -f $(TARGET) sum.o