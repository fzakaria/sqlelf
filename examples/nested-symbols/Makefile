# Variables
CC = gcc
CFLAGS = -Wall -O2
TARGET = exe
SRC = nested.c

# Default rule
all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $<

.PHONY: clean
clean:
	rm -f $(TARGET)