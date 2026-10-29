#! /bin/bash

set -e

hatch env create
npm ci

hatch run python scripts/init-dev-env.py
hatch run python -m fief.cli migrate

set +e
hatch run translations.compile
hatch run python -m fief.cli create-admin --user-email anne@bretagne.duchy --user-password herminetincture
set -e
