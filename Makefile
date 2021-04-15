.PHONY: fresh

SHELL := /bin/bash

fresh:
	ENV=LOCAL \
	PORT=8041 \
	VERSION=VERSION \
	fresh
