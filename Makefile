all:
	$(MAKE) -C src

tests: test_crypt test_sql

test_crypt:
	$(MAKE) -C src

test_sql:
	$(MAKE) -C src

clean:
	rm -f *.o $(TARGET) $(TEST_TARGET_CRYPT) $(TEST_TARGET_SQL)
