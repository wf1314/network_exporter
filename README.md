# [Prometheus](https://prometheus.io) Exporter

## Prometheus Configuration
```
scrape_configs:
  - job_name: 'blackbox'
    metrics_path: /probe
    params:
      status_code: [200, ]  # Look for a HTTP 200 response.
      ic_code: [yaicn]
      proxy: [http://wangfan:123456@47.95.248.13:19000]
      headers: ['{}']
      request_data: ['{}']
      request_method: [GET]
      response_data: []
      response_coding: [utf8]
      timeout: [10]
      name: []
    static_configs:
      - targets:
        - https://www.baidu.com    # Target to
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: 127.0.0.1:9116  # The network exporter's real hostname:port.
```

## Local Run
```
make build
make start
```

## Checking the results

```
curl http://localhost:9116/probe?target=www.baidu.com&proxy=http://wangfan:123456@47.95.248.13:19000
```