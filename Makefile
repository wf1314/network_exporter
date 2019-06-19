build:
	docker build -t net:v1 .

start_dev:
	docker run --rm -d -p 9118:9118  --expose 9118 -v $(shell pwd):/srv/Network_Exporter net:v1  python /srv/Network_Exporter/network_exporter.py --port=9118 --addr="0.0.0.0" --log_dir="/srv/Network_Exporter/network_log/"

start:
	docker run -d -p 9116:9116 -v ~/network_log:/tmp/network_log net:v1

test:
	docker run -it --rm net:v1 /bin/sh
