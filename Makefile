all:
	$(MAKE) -C src all

tests: test_crypt test_sql

test_crypt:
	$(MAKE) -C src test_crypt

test_sql:
	$(MAKE) -C src test_sql

clean:
	$(MAKE) -C src clean
