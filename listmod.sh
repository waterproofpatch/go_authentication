#!/bin/bash
# Obtain the pre-release module path for early access developers to use.
hash=$(git rev-parse HEAD)
go list -m -json github.com/waterproofpatch/go_authentication@$hash