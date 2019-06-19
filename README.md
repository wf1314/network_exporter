# network_exporter

## 用于校验代理可用性

## Prometheus Configuration
```
scrape_configs:
  - job_name: 'blackbox'
    metrics_path: /probe
    params:
      status_code: [200, ]  # Look for a HTTP 200 response.
      ic_code: [yaicn]
      proxy: [http=user:password@39.96.88.88:9000]
      headers: ['{}']
      request_data: ['{}']
      request_method: [GET]
      response_data: [ttttttt]
      response_coding: [utf8]
      timeout: [50]
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
