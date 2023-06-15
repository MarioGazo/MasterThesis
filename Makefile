PYTHON=/usr/bin/python3.7
MAIN=main.py
PIP=$(PYTHON) -m pip
PYTEST=$(PYTHON) -m pytest
REQUIREMENTS=requirements.txt
ZIP_FILE=s212687.zip

exp: exp-tds exp-es

exp-tds:
	$(PYTHON) $(MAIN) TDS

exp-es:
	$(PYTHON) $(MAIN) ES

test: test-tlp test-es test-tds

test-tlp:
	$(PYTEST) src/TLP

test-es:
	$(PYTEST) src/schemes/ES

test-tds:
	$(PYTEST) src/schemes/TDS

clean:
	find . -type d -name .pytest_cache -exec rm -r {} \+
	find . -type d -name __pycache__ -exec rm -r {} \+
	find . -type f -name .DS_Store -exec rm -r {} \+

install:
	$(PIP) install -r $(REQUIREMENTS)

submit: clean
	zip -r $(ZIP_FILE) src out Makefile Dockerfile main.py README.md requirements.txt

lines:
	git ls-files | xargs file | grep "ASCII" | cut -d : -f 1 | xargs wc -l
