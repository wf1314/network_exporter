# -*- coding:utf-8 -*-
# ===============================================================================
#  Author: WangFan <sgwf525@126.com>
#  Version: 0.1
#  Description: Prometheus Exporter
#  Environment: Python 3.7
#  Change Log:
#      2019-06-19
#          0.1 完成
# ===============================================================================
import os
import json
import time
import pycurl
import logging
from typing import Optional
from datetime import timedelta
from urllib.parse import urlencode

from tornado import gen
from tornado.ioloop import IOLoop
from tornado.web import RequestHandler
from tornado.web import Application
from tornado.options import define
from tornado.options import options
from tornado.log import LogFormatter
from logging.handlers import RotatingFileHandler
from tornado.httpclient import HTTPRequest
from tornado.httpclient import HTTPResponse
from tornado.curl_httpclient import CurlAsyncHTTPClient


async def is_network(timeout: int = 3) -> bool:
    """验证本机的网络是否通畅"""
    url = 'www.baidu.com'
    client = CurlAsyncHTTPClient(force_instance=True)
    request = HTTPRequest(
        url, request_timeout=timeout, connect_timeout=timeout
    )
    future = client.fetch(request, raise_error=False)
    try:
        resp = await gen.with_timeout(timedelta(seconds=timeout), future)
        return resp.code == 200
    except gen.TimeoutError:
        return False


def deal_args(args: dict) -> dict:
    """
    处理get参数
    :param args:
    :return:
    """
    for k, v in args.items():
        new_v = []
        for i in v:
            i = i.decode()
            new_v.append(i)
        if not new_v:
            args[k] = ''
        elif k == 'status_code':
            args[k] = [i.decode() for i in v]
        elif len(new_v) == 1:
            args[k] = new_v[0]
    return args


def format_proxy(proxy_str: str) -> dict:
    """
    格式化代理
    :param proxy_str:
    :return:
    """
    output = {}

    proxy_info_list = proxy_str.split('=')
    output['proxy_type'] = proxy_info_list[0]

    if '@' in proxy_str:
        proxy_ip_info_list = proxy_info_list[1].split('@')
        output['host'], output['port'] = proxy_ip_info_list[1].split(':')
        output['port'] = int(output['port'])

        if len(proxy_ip_info_list) == 2:
            output['proxy_user'], output['proxy_pwd'] = (
                proxy_ip_info_list[0].split(':')
            )

    else:
        output['host'], output['port'] = proxy_info_list[1].split(':')
        output['port'] = int(output['port'])

    return output


def get_urlencoded_body(data: dict) -> str:
    """
    data字典转为字符串
    :param data:
    :return:
    """
    if not data:
        return None
    result = []
    data = data.items() if isinstance(data, dict) else data

    for key, val in data:
        if val is not None:
            result.append((key, val))

    return urlencode(result)


def return_result_tmp(resp: Optional[HTTPResponse],
                      all_time: str,
                      status_code_list: list,
                      response_data: str
                      ) -> str:
    """
    构造响应内容
    :param response_data:
    :param status_code_list:
    :param resp:
    :param all_time:
    :return:
    """
    if not resp:
        time_info = {
            'connect': '0',
            'namelookup': '0',
            'redirect': '0',
            'total': '0',
            'pretransfer': '0',
            'starttransfer': '0',
        }
        content_length = 0
        is_sucss = 0
        resp_code = 0
    else:
        time_info = resp.time_info
        content_length = len(resp.body) if resp.body else 0
        is_sucss = str(resp.code) in status_code_list and response_data in resp.text
        resp_code = resp.code
    output = f"# Returns the time taken for probe dns lookup in seconds\n" \
             f"probe_duration_seconds {all_time}\n" \
             f"# Returns how long the probe took to complete in seconds\n" \
             f"probe_http_content_length {content_length}\n" \
             f"# Duration of http request by phase, summed over all redirects\n" \
             f"""probe_http_duration_seconds{'{phase="connect"}'} {time_info["connect"]}\n""" \
             f"""probe_http_duration_seconds{'{phase="namelookup"}'} {time_info["namelookup"]}\n""" \
             f"""probe_http_duration_seconds{'{phase="redirect"}'} {time_info["redirect"]}\n""" \
             f"""probe_http_duration_seconds{'{phase="total"}'} {time_info["total"]}\n""" \
             f"""probe_http_duration_seconds{'{phase="pretransfer"}'} {time_info["pretransfer"]}\n""" \
             f"""probe_http_duration_seconds{'{phase="transfer"}'} {time_info["starttransfer"]}\n""" \
             f"# Response HTTP status code\n" \
             f"probe_http_status_code {resp_code}\n" \
             f"# Displays whether or not the probe was a success eg:success 0 \n" \
             f"probe_success {abs(int(is_sucss)-1)}\n"
    return output


def get_logger(file: str):
    """
    获取日志对象
    :return:
    """
    log_dir = file

    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    log = logging.getLogger(__name__)
    log.setLevel(logging.DEBUG)
    log_file = os.path.join(log_dir, 'log.log')
    handler = RotatingFileHandler(log_file, maxBytes=1024 * 1024 * 30, backupCount=10)
    default_format = '%(color)s[%(levelname)1.1s %(asctime)s.%(msecs)03d %(module)s:%(lineno)d]%(end_color)s %(' \
                     'message)s '
    handler.setFormatter(LogFormatter(color=True, fmt=default_format))
    log.addHandler(handler)
    log.info('----------初始化日志-----------')
    return log


class MainHandler(RequestHandler):
    """"""
    def initialize(self):
        """
        初始化
        :return:
        """
        self.logger = logger

    async def get(self):
        """
        get请求
        :return:
        """
        st = time.time()
        args = deal_args(self.request.arguments)
        self.logger.debug(self.get_arguments)
        self.logger.debug(self.request.arguments)

        headers = json.loads(args.get('headers', '{}'))
        data = json.loads(args.get('request_data', '{}'))
        method = args.get('request_method', 'GET')
        proxy = args.get('proxy', '')
        response_data = args.get('response_data', '')
        resp_coding = args.get('response_coding', 'utf8')
        status_code_list = args.get('status_code', ['200'])
        timeout = int(args.get('timeout', 10))
        proxy_dict = format_proxy(proxy)
        url = args.get('target', 'http://www.baidu.com')

        resp = await self.use_proxy_request(url, method, data, headers, timeout, proxy_dict, resp_coding)
        all_time = str(time.time() - st)  # 探测完成所需的时间
        output = return_result_tmp(resp, all_time, status_code_list, response_data)
        self.logger.debug(output)
        self.set_header("Content-Type", "text/plain; version=0.0.4")
        self.write(output)

    def make_request(self,
                     url: str,
                     method: str,
                     data: dict,
                     headers: dict,
                     timeout: int,
                     proxy: dict,
                     ) -> HTTPRequest:
        """
        构造request对象
        :param url:
        :param method:
        :param data:
        :param headers:
        :param timeout:
        :param proxy:
        :return:
        """
        data = get_urlencoded_body(data)
        request = HTTPRequest(
            url, method=method, headers=headers, body=data, request_timeout=timeout,
            connect_timeout=timeout
        )
        request.proxy_host = proxy['host']
        request.proxy_port = proxy['port']
        if proxy.get('proxy_user'):
            request.proxy_username = proxy['proxy_user']
            request.proxy_password = proxy['proxy_pwd']

        if proxy['proxy_type'] == 'socks5':
            request.prepare_curl_callback = (
                lambda c: c.setopt(pycurl.PROXYTYPE, pycurl.PROXYTYPE_SOCKS5)
            )
        request.validate_cert = False
        request.follow_redirects = False
        return request

    async def use_proxy_request(self,
                                url: str,
                                method: str,
                                data: dict,
                                headers: dict,
                                timeout: int,
                                proxy_dict: dict,
                                resp_encoding: str,
                                ) -> Optional[HTTPResponse]:
        """
        检查代理状态
        :param url:
        :param method:
        :param data:
        :param headers:
        :param timeout:
        :param proxy_dict:
        :param resp_encoding:
        :return:
        """
        client = CurlAsyncHTTPClient(force_instance=True)
        request = self.make_request(url, method, data, headers, timeout, proxy_dict)
        time_msg = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        try:
            resp = await client.fetch(request, raise_error=False)
            msg = (
                '{} ===> host: {}:{}, url: {} ,result: {}'.format(
                    time_msg, proxy_dict['host'], proxy_dict['port'],
                    url, resp.code
                )
            )
            self.logger.debug(msg)
        except Exception as e:
            time_msg = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            self.logger.error(
                '{} ===> host: {}:{}, url: {}, result: {}'.format(
                    time_msg, proxy_dict['host'], proxy_dict['port'],
                    url, str(e)
                )
            )
            return
        return self.get_response_data(resp, resp_encoding)

    def get_response_data(self, resp: HTTPResponse, resp_encoding: str) -> HTTPResponse:
        """
        构造r.text
        :param resp:
        :param resp_encoding:
        :return:
        """
        resp._resp_charset = self._get_charset(resp.headers.get("Content-Type", ''), resp_encoding)

        # 减少不必要的转换
        type(resp).text = property(lambda x: x.body.decode(x._resp_charset, errors='ignore'))
        return resp

    def _get_charset(self, content_type: str, resp_encoding: str) -> str:
        """
        返回r.text编码
        :param content_type:
        :param resp_encoding:
        :return:
        """
        if content_type and len(content_type.split('charset=')) == 2:
            return content_type.split('charset=')[1]
        else:
            return resp_encoding


def main():
    define("addr", default='0.0.0.0', type=str, help="run server on the given address.")  # 定义服务器监听端口选项
    define("port", default=9116, type=int, help="run server on the given port.")  # 定义服务器监听端口选项
    define("log_dir", default="/tmp/network_log", type=str, help="log directory")
    options.parse_config_file('./config')
    options.parse_command_line()
    global logger
    logger = get_logger(options.log_dir)
    application = Application([
        (r"/probe", MainHandler),
    ])  # 路由规则

    application.listen(options.port, address=options.addr)
    IOLoop.current().start()


if __name__ == "__main__":

    main()
