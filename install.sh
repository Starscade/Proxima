#!/bin/sh

mkdir -p ~/.local/bin &&
go mod tidy &&
go fmt &&
CGO_ENABLED=0 go build \
-ldflags="-s -w" \
	-o ~/.local/bin/Proxima \
	-v \
	-x
