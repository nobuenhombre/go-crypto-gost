#!/bin/bash

## https://pkg.go.dev/golang.org/x/tools/cmd/goimports?tab=doc
## go get golang.org/x/tools/cmd/goimports

goimports -v -w $(go list -f {{.Dir}} ./...)
