VENV := .venv
PYTHON := $(VENV)/bin/python
ifeq ($(OS),Windows_NT)
    PYTHON := $(VENV)/Scripts/python.exe
endif

.PHONY: venv install run stop debug clean test

venv: $(VENV)/pyvenv.cfg

$(VENV)/pyvenv.cfg:
	python -m venv $(VENV)
	$(PYTHON) -m pip install --upgrade pip uv

install: venv
	$(PYTHON) -m uv pip install -r requirements.txt

build:
	docker compose build

run: build
	docker compose up -d

stop:
	docker compose down

debug: install
	$(PYTHON) -m run