all:
	$(MAKE) -C src all

tests: test_crypt test_BIP84 test_sql test_user

test_crypt:
	$(MAKE) -C src test_crypt

test_BIP84:
	$(MAKE) -C src test_BIP84

test_sql:
	$(MAKE) -C src test_sql

test_user:
	$(MAKE) -C src test_user

clean:
	$(MAKE) -C src clean
