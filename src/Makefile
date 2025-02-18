CC=gcc
FILES=BIP173.c wall_e_t_crypto.c wall_e_t_sql.c wall_e_t_user.c wall_e_t_net.c main.c
TEST_CRYPT_FILES=BIP173.c wall_e_t_crypto.c test_crypto.c
TEST_BIP84_FILES=BIP173.c wall_e_t_crypto.c test_BIP84.c
TEST_SQL_FILES=BIP173.c wall_e_t_crypto.c wall_e_t_user.c wall_e_t_sql.c wall_e_t_net.c test_sql.c
TEST_USER_FILES=BIP173.c wall_e_t_crypto.c wall_e_t_user.c wall_e_t_sql.c wall_e_t_net.c test_user.c
TEST_NET_FILES=BIP173.c wall_e_t_crypto.c wall_e_t_net.c test_net.c
TGT_FOLDER=../
TARGET=wall_e_t
TEST_TARGET_CRYPT=test_crypto
TEST_TARGET_BIP84=test_BIP84
TEST_TARGET_SQL=test_sql
TEST_TARGET_USER=test_user
TEST_TARGET_NET=test_net
CFLAGS=-Wall -Werror
LIBS=-lgcrypt -lsqlite3 -lcurl
LIBS_FOLDER = -L /usr/local/lib
INCLUDE=-I ./ -I /usr/include

wallet:
	$(CC) $(CFLAGS) -o $(TGT_FOLDER)$(TARGET) $(FILES) $(LIBS) $(INCLUDE)

tests: test_crypt test_BIP84 test_sql test_user test_net

test_crypt:
	$(CC) $(CFLAGS) -o $(TGT_FOLDER)$(TEST_TARGET_CRYPT) $(TEST_CRYPT_FILES) $(LIBS) $(INCLUDE)

test_BIP84:
	$(CC) $(CFLAGS) -o $(TGT_FOLDER)$(TEST_TARGET_BIP84) $(TEST_BIP84_FILES) $(LIBS) $(INCLUDE)

test_sql:
	$(CC) $(CFLAGS) -o $(TGT_FOLDER)$(TEST_TARGET_SQL) $(TEST_SQL_FILES) $(LIBS) $(INCLUDE)

test_user:
	$(CC) $(CFLAGS) -o $(TGT_FOLDER)$(TEST_TARGET_USER) $(TEST_USER_FILES) $(LIBS) $(INCLUDE)

test_net:
	$(CC) $(CFLAGS) -o $(TGT_FOLDER)$(TEST_TARGET_NET) $(TEST_NET_FILES) $(LIBS) $(INCLUDE)

clean:
	rm -f *.o $(TGT_FOLDER)$(TARGET) $(TGT_FOLDER)$(TEST_TARGET_CRYPT) $(TGT_FOLDER)$(TEST_TARGET_BIP84) $(TGT_FOLDER)$(TEST_TARGET_SQL) $(TGT_FOLDER)$(TEST_TARGET_USER) $(TGT_FOLDER)$(TEST_TARGET_NET)
