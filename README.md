# auditd_exporter
it loads a set of auditd rules, collects events from the kernel and expose them 

A basic set of rules can be:
https://github.com/maurorappa/libaudit-go/blob/master/testdata/rules.json


to run:
sudo go run audit_exporter.go rules.json

