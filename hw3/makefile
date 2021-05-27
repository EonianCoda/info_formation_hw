VENV := venv
MKDIR = mkdir -p
.PHONY: all enc dec

all: enc dec

install: venv
	# Activate venv and install package
	./$(VENV)/Scripts/activate.bat & pip install -r requirements.txt

venv: 
	python -m venv $(VENV)

enc:
	${MKDIR} test_enc
	./$(VENV)/Scripts/activate.bat & python enc.py ./linux.jpeg -m ECB -o ./test_enc/ECB.png -e E
	python enc.py ./linux.jpeg -m CTR -o ./test_enc/CTR.png -e E
	python enc.py ./linux.jpeg -m CBC -o ./test_enc/CBC.png -e E
	python enc.py ./linux.jpeg -m OFB -o ./test_enc/OFB.png -e E
	python enc.py ./linux.jpeg -m COOL -o ./test_enc/COOL.png -e E
					
dec:
	${MKDIR} test_dec
	python dec.py ./test_enc/ECB.png -m ECB -o ./test_dec/ECB.png -e D
	python dec.py ./test_enc/CTR.png -m CTR -o ./test_dec/CTR.png -e D
	python dec.py ./test_enc/CBC.png -m CBC -o ./test_dec/CBC.png -e D
	python dec.py ./test_enc/OFB.png -m OFB -o ./test_dec/OFB.png -e D
	python dec.py ./test_enc/COOL.png -m COOL -o ./test_dec/COOL.png -e D

clean:
	rm -rf $(VENV)
	find . -type f -name "*.pyc"