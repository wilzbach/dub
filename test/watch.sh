#!/bin/bash

TEST_DIR="$(dirname "$0")"
COUNTER="$TEST_DIR"/watch/source/counter.d
echo 'enum count = 0;' > "$COUNTER"
# need force here, because the modtime change is too small
$DUB watch --root="$TEST_DIR/watch" --compiler="$COMPILER" --force
if [ "$(cat "$COUNTER")" != "enum count = 3;" ] ; then
    echo "Invalid counter state."
    echo "Counter is: $(cat "$COUNTER")"
    exit 1
fi
