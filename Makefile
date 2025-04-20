CC = gcc
CFLAGS = -Wall -g `pkg-config --cflags gtk+-3.0`
INCLUDES = -Iinclude
LIBS = -lpcap `pkg-config --libs gtk+-3.0`
SRCS = src/main.c src/capture.c src/gui.c src/shared.c
TARGET = build/minishark

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) $(INCLUDES) -o $(TARGET) $(SRCS) $(LIBS)

clean:
	rm -f $(TARGET) src/*.o