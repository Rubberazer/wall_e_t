CC=gcc
FILES=wall_e_t_crypt.c main.c
TEST_FILES=wall_e_t_crypt.c test.c
TARGET=wall_e_t
TEST_TARGET=test
CFLAGS=-Wall -Werror
LIBS=-lgcrypt
INCLUDE=-I ./ -I /usr/include

all:
	$(CC) $(CFLAGS) -o $(TARGET) $(FILES) $(LIBS) $(INCLUDE)

test:
	$(CC) $(CFLAGS) -o $(TEST_TARGET) $(TEST_FILES) $(LIBS) $(INCLUDE)

clean:
	rm -f *.o $(TARGET) $(TEST_TARGET)
