
tests:
	pytest tests.py

tests-production:
	ENV=production pytest tests.py

test-single:
	pytest tests.py::test_challenge_open_submit_exploit

.PHONY: tests tests-production test-single
