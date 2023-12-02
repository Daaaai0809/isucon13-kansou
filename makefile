all: rotate-all app-deploy

.PHONY: rotate-all
rotate-all: rotate-access-log rotate-slow-log

.PHONY: rotate-access-log
rotate-access-log:
	echo "Rotating access log"
	sudo mv /var/log/nginx/access.ndjson /var/log/nginx/access.ndjson.$(shell date +%Y%m%d)
	sudo rm /var/log/nginx/access.ndjson
	sudo systemctl restart nginx
	

.PHONY: rotate-slow-log
rotate-slow-log:
	echo "Rotating slow log"
	sudo mv /var/log/mysql/mysql-slow.log /var/log/mysql/mysql-slow.log.$(shell date +%Y%m%d)
	sudo rm /var/log/mysql/mysql-slow.log
	sudo systemctl restart mysql

.PHONY: alp
alp:
	alp json --config ./alp-config.yml

.PHONY: pt
pt:
	sudo pt-query-digest /var/log/mysql/mysql-slow.log

.PHONY: pprof
pprof:
	cd /home/isucon/webapp/go &&
	go tool pprof -seconds 90 -http=localhost:1080 http://localhost:6060/debug/pprof/profile

.PHONY: init-pd
init-pd:
	echo "Initializing pd"
	cd /home/isucon/webapp/pdns && ./init_zone.sh

.PHONY: app-deploy
app-deploy:
	echo "Deploying app"
	cd /home/isucon/webapp/go && make build
	sudo systemctl restart nginx
	sudo systemctl restart mysql
	sudo systemctl restart isupipe-go.service
