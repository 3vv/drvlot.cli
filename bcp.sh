#!/usr/bin/env bash
D="$GOPATH/src/bcp"
S="$PWD/../drvlot.bcp"
rm -f "$D"
ln -sF "$S" "$D"