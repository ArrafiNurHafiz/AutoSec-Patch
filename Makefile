.PHONY: install test lint format docker-build all

install:
	pip install -e .[dev]

test:
	python -m unittest discover tests/

lint:
	flake8 autosec climatetrust tests --max-line-length=120
	black --check autosec climatetrust tests

format:
	black autosec climatetrust tests

docker-build:
	docker build -t autosec-patch .

all: format lint test
