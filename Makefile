wallet:
	$(MAKE) -C src wallet

tests:
	$(MAKE) -C src tests

test_crypt:
	$(MAKE) -C src test_crypt

test_BIP84:
	$(MAKE) -C src test_BIP84

test_sql:
	$(MAKE) -C src test_sql

test_user:
	$(MAKE) -C src test_user

test_net:
	$(MAKE) -C src test_net

clean:
	$(MAKE) -C src clean
