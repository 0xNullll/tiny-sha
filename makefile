# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -O2

TARGET = sha_test

SRC = tiny_sha.c sha_test.c

OBJ = $(SRC:.c=.o)

all: $(TARGET)

# Build the executable
$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean objects and executable
clean:
ifeq ($(OS),Windows_NT)
	del /Q $(OBJ) $(TARGET).exe
else
	rm -f $(OBJ) $(TARGET)
endif

.PHONY: all clean
