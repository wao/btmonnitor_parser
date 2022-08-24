.PHONY: strip default

default: bt.log

strip: result.log

bt.log: result.log
	python3 btmonitor_parser/parser.py result.log

result.log : my_fg.log
	scripts/strip_jlink_comment my_fg.log result.log



