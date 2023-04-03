#!/bin/sh

set -e
python3 -m pytest . -vv -s --disable-warnings
