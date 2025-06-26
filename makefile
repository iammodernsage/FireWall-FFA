build:
	gcc core-engine/waf.c core-engine/waf_rules.c -o core-engine/waf -Wall -Icore-engine

run:
	python3 cli-tool/firewallctl.py start

stop:
	python3 cli-tool/firewallctl.py stop

status:
	python3 cli-tool/firewallctl.py status

reload:
	python3 cli-tool/firewallctl.py reload

install:
	bash scripts/install.sh
