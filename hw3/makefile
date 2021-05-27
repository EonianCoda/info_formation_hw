VENV := venv
MKDIR = mkdir -p
.PHONY: all enc dec

all: enc dec

install: venv
	sudo apt install python3-pip
	# Activate venv and install package
	. $(VENV)/bin/activate && pip3 install -r requirements.txt

venv:
	sudo apt-get install python3-venv	
	python3 -m venv $(VENV)

enc:
	${MKDIR} test_enc
	(. $(VENV)/bin/activate; \
	python3 enc.py ./linux.jpeg -m ECB -o ./test_enc/ECB.png -e E; \
	python3 enc.py ./linux.jpeg -m CTR -o ./test_enc/CTR.png -e E; \
	python3 enc.py ./linux.jpeg -m CBC -o ./test_enc/CBC.png -e E; \
	python3 enc.py ./linux.jpeg -m OFB -o ./test_enc/OFB.png -e E; \
	python3 enc.py ./linux.jpeg -m COOL -o ./test_enc/COOL.png -e E; \
	)
					
dec:
	${MKDIR} test_dec
	(. $(VENV)/bin/activate; \
	python3 dec.py ./test_enc/ECB.png -m ECB -o ./test_dec/ECB.png -e D; \
	python3 dec.py ./test_enc/CTR.png -m CTR -o ./test_dec/CTR.png -e D; \
	python3 dec.py ./test_enc/CBC.png -m CBC -o ./test_dec/CBC.png -e D; \
	python3 dec.py ./test_enc/OFB.png -m OFB -o ./test_dec/OFB.png -e D; \
	python3 dec.py ./test_enc/COOL.png -m COOL -o ./test_dec/COOL.png -e D;\
	)

clean:
	rm -rf $(VENV) __pycache__ test_dec test_enc
