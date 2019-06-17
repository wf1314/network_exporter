import requests


def test():
    url = 'http://localhost:9116/probe'
    data = {
        'target': 'https://icar.epicc.com.cn:8443/icar/saaUserPower/login.do',
        'headers': '{}',
        'ic_code': 'yaicn',
        'proxy': 'http=Botpy:lDZb3prDT7LMm1vukIHf9X@39.96.74.60:9000',
        'request_data': '{}',
        'request_method': 'GET',
        'response_data': '',
        'status_code': ['200'],
        'timeout': '5',
        'resp_encoding': 'utf-8',  # 默认utf8
    }
    r = requests.get(url, params=data)
    print(r.text)
    assert r.text.strip('\n')[-1] == '0'


if __name__ == '__main__':
    test()