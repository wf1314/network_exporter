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

## Checking the results chart

```
curl http://localhost:9116/probe?target=www.baidu.com&proxy=http://wangfan:123456@47.95.248.13:19000&chart=1
```
```
          DNS Lookup   TCP Connection   TLS Handshake   Server Processing   Content Transfer
        [     1ms    |       8ms      |      0ms      |       13ms        |        8ms       ]
                     |                |               |                   |                  |
            namelookup:1ms            |               |                   |                  |
                                connect:9ms           |                   |                  |
                                            pretransfer:9ms               |                  |
                                                              starttransfer:23ms             |
                                                                                         total:31ms

```

## Checking the results 
```
curl http://localhost:9116/probe?target=www.baidu.com&proxy=http://wangfan:123456@47.95.248.13:19000
```
```
# HELP probe_dns_lookup_time_seconds Returns the time taken for probe dns lookup in seconds
# TYPE probe_dns_lookup_time_seconds gauge
probe_dns_lookup_time_seconds 0.023714772
# HELP probe_duration_seconds Returns how long the probe took to complete in seconds
# TYPE probe_duration_seconds gauge
probe_duration_seconds 0.106005898
# HELP probe_failed_due_to_regex Indicates if probe failed due to regex
# TYPE probe_failed_due_to_regex gauge
probe_failed_due_to_regex 0
# HELP probe_http_content_length Length of http content response
# TYPE probe_http_content_length gauge
probe_http_content_length -1
# HELP probe_http_duration_seconds Duration of http request by phase, summed over all redirects
# TYPE probe_http_duration_seconds gauge
probe_http_duration_seconds{phase="connect"} 0.006734189
probe_http_duration_seconds{phase="processing"} 0.066601639
probe_http_duration_seconds{phase="resolve"} 0.023714772
probe_http_duration_seconds{phase="tls"} 0
probe_http_duration_seconds{phase="transfer"} 0.008547172
# HELP probe_http_redirects The number of redirects
# TYPE probe_http_redirects gauge
probe_http_redirects 0
# HELP probe_http_ssl Indicates if SSL was used for the final redirect
# TYPE probe_http_ssl gauge
probe_http_ssl 0
# HELP probe_http_status_code Response HTTP status code
# TYPE probe_http_status_code gauge
probe_http_status_code 200
# HELP probe_http_version Returns the version of HTTP of the probe response
# TYPE probe_http_version gauge
probe_http_version 1.1
# HELP probe_ip_protocol Specifies whether probe ip protocol is IP4 or IP6
# TYPE probe_ip_protocol gauge
probe_ip_protocol 4
# HELP probe_success Displays whether or not the probe was a success
# TYPE probe_success gauge
probe_success 1
```
