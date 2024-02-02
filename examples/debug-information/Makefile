# Variables
CC = g++
CFLAGS = -Wall -g
TARGET = exe
SRC = debug.cc

# Default rule
all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $<

.PHONY: clean
clean:
	rm -f $(TARGET)