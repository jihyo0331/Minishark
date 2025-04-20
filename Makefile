CC = gcc
CFLAGS = -Wall -g
INCLUDES = -Iinclude
LIBS = -lpcap

SRCS = src/main.c src/capture.c
OBJS = $(SRCS:.c=.o)
TARGET = build/minishark

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) $(INCLUDES) -o $(TARGET) $(SRCS) $(LIBS)

clean:
	rm -f $(TARGET) src/*.o