SAGEFILES := $(basename $(notdir $(wildcard *.sage)))
PYFILES := $(addprefix sagelib/, $(addsuffix .py,$(SAGEFILES)))
.PRECIOUS: $(PYFILES)

.PHONY: pyfiles
pyfiles: sagelib/__init__.py $(PYFILES)

sagelib/__init__.py:
	mkdir -p sagelib
	echo pass > sagelib/__init__.py

sagelib/%.py: %.sage
	@echo "Parsing $<"
	@sage --preparse $<
	@mv $<.py $@

setup:
	cp h2c/poc/hash_to_field.py .
	cp h2c/poc/*.sage .

test: pyfiles
	sage test_athm.sage

vectors: pyfiles
	@echo "Removing vectors folder, if present"
	@rm -rf vectors
	@echo "Creating vectors folder"
	@mkdir -p vectors
	sage test_athm.sage

.PHONY: clean
clean:
	rm -rf sagelib *.pyc *.sage.py *.log __pycache__

.PHONY: distclean
distclean: clean
	rm -rf vectors ascii