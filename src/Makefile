CC=gcc
FILES=BIP173.c wall_e_t_crypto.c wall_e_t_sql.c wall_e_t_user.c main.c
TEST_CRYPT_FILES=BIP173.c wall_e_t_crypto.c test_crypto.c
TEST_SQL_FILES= wall_e_t_user.c wall_e_t_sql.c test_sql.c
TGT_FOLDER=../
TARGET=wall_e_t
TEST_TARGET_CRYPT=test_crypto
TEST_TARGET_SQL=test_sql
CFLAGS=-Wall -Werror
LIBS=-lgcrypt -lsqlite3
INCLUDE=-I ./ -I /usr/include

all:
	$(CC) $(CFLAGS) -o $(TGT_FOLDER)$(TARGET) $(FILES) $(LIBS) $(INCLUDE)

test: test_crypt test_sql

test_crypt:
	$(CC) $(CFLAGS) -o $(TGT_FOLDER)$(TEST_TARGET_CRYPT) $(TEST_CRYPT_FILES) $(LIBS) $(INCLUDE)

test_sql:
	$(CC) $(CFLAGS) -o $(TGT_FOLDER)$(TEST_TARGET_SQL) $(TEST_SQL_FILES) $(LIBS) $(INCLUDE)

clean:
	rm -f *.o $(TGT_FOLDER)$(TARGET) $(TGT_FOLDER)$(TEST_TARGET_CRYPT) $(TGT_FOLDER)$(TEST_TARGET_SQL)
