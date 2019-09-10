#!/bin/bash
antlr4 -Dlanguage=Python3 grammars/openflowParser.g4 grammars/openflowLexer.g4  -package openflow_analysis -no-listener
mv grammars/*.py openflow_analysis/
