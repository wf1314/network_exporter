# -*- coding:utf-8 -*-
"""
# ===============================================================================
#  Author: WangFan <sgwf525@126.com>
#  Version: 0.1
#  Description: 用于检测代理连接是否正常
#  Environment: Python 3.7
#  Change Log:
#      2019-06-19
#           完成
#      2019-07-02
#           修改返回数据模板
# ===============================================================================
"""
import os
import json
import time
import pycurl
import logging
from typing import Optional
from urllib.parse import urlencode

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

    def initialize(self, **kwargs):
        """
        初始化
        :return:
        """
        self.logger = kwargs.get('logger')
        self.response_message = ''  # 记录完整响应报文

    def deal_args(self) -> dict:
        """
        处理get参数
        :param args:
        :return:
        """
        args = self.request.arguments
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

    @staticmethod
    def format_proxy(proxy_str: str) -> dict:
        """
        格式化代理
        :param proxy_str:
        :return:
        """
        output = {}
        proxy_info_list = proxy_str.split('://')
        output['proxy_type'] = proxy_info_list[0]
        if not proxy_str:
            return {}
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

    async def get(self):
        """
        get请求
        :return:
        """
        st = time.time()
        args = self.deal_args()
        self.logger.debug(self.request.arguments)
        headers = json.loads(args.get('headers', '{}'))
        data = json.loads(args.get('request_data', '{}'))
        method = args.get('request_method', 'GET')
        response_body = args.get('response_body', '')
        resp_coding = args.get('response_coding', 'utf8')
        status_code_list = args.get('status_code', ['200'])
        timeout = int(args.get('timeout', 10))
        url = args.get('target', 'http://www.baidu.com')
        proxy = args.get('proxy', '')
        chart = args.get('chart', '')
        proxy_dict = self.format_proxy(proxy)
        resp = await self.use_proxy_request(url, method, data, headers, timeout, proxy_dict, resp_coding)
        current_time = f'{time.time():.8e}'
        all_time = str(time.time() - st)  # 探测完成所需的时间
        output = self.return_result_tmp(resp, all_time, current_time, status_code_list, response_body, chart)
        self.logger.debug(output)
        self.set_header("Content-Type", "text/plain; version=0.0.4")
        self.write(output)

    def deal_time_info(self, time_info) -> dict:
        """
        处理时间信息
        :param time_info:
        :return:
        """
        as_num = lambda x: '{:.6f}'.format(x)
        dns_lookup = time_info["namelookup"]
        namelookup = time_info["namelookup"]
        tcp_connection = as_num(float(time_info["connect"]) - float(time_info["namelookup"]))
        connect = time_info["connect"]
        ssl_handshake = as_num(float(time_info['pretransfer']) - float(time_info["connect"]))
        pretransfer = time_info['pretransfer']
        server_processing = as_num(float(time_info['starttransfer']) - float(time_info['pretransfer']))
        starttransfer = time_info['starttransfer']
        content_transfer = as_num(float(time_info['total']) - float(time_info['starttransfer']))
        total = time_info['total']
        output = {
            'dns_lookup': dns_lookup,
            'namelookup': namelookup,
            'tcp_connection': tcp_connection,
            'connect': connect,
            'tls_handshake': ssl_handshake,
            'pretransfer': pretransfer,
            'server_processing': server_processing,
            'starttransfer': starttransfer,
            'content_transfer': content_transfer,
            'total': total,
        }
        time_info.update(output)
        return time_info

    def return_result_amity(self, time_info) -> str:
        """
        返回结果
        :return:
        """
        template = """
          DNS Lookup   TCP Connection   TLS Handshake   Server Processing   Content Transfer
        [   {a0000}  |     {a0001}    |    {a0002}    |      {a0003}      |      {a0004}     ]
                     |                |               |                   |                  |
            namelookup:{b0000}        |               |                   |                  |
                                connect:{b0001}       |                   |                  |
                                            pretransfer:{b0002}           |                  |
                                                              starttransfer:{b0003}          |
                                                                                         total:{b0004}
        """
        fmta = lambda x: '{:^7}'.format(str(int(float(x) * 1000)) + 'ms')
        fmtb = lambda x: '{:<7}'.format(str(int(float(x) * 1000)) + 'ms')
        stat = template.format(
            # a
            a0000=fmta(time_info['dns_lookup']),
            a0001=fmta(time_info['tcp_connection']),
            a0002=fmta(time_info['tls_handshake']),
            a0003=fmta(time_info['server_processing']),
            a0004=fmta(time_info['content_transfer']),
            # b
            b0000=fmtb(time_info['namelookup']),
            b0001=fmtb(time_info['connect']),
            b0002=fmtb(time_info['pretransfer']),
            b0003=fmtb(time_info['starttransfer']),
            b0004=fmtb(time_info['total']),
        )
        self.logger.info(stat)
        return stat

    def return_result_tmp(self,
                          resp: Optional[HTTPResponse],
                          all_time: str,
                          current_time: str,
                          status_code_list: list,
                          response_body: str,
                          chart: str
                          ) -> str:
        """
        构造响应内容
        :param response_body:
        :param status_code_list:
        :param resp:
        :param all_time:
        :return:
        """
        if not resp:
            time_info = {
                'dns_lookup': '0',
                'namelookup': '0',
                'tcp_connection': '0',
                'connect': '0',
                'tls_handshake': '0',
                'pretransfer': '0',
                'server_processing': '0',
                'starttransfer': '0',
                'content_transfer': '0',
                'total': '0',
                'redirect': '0',
            }
            content_length = 0
            is_sucss = 0
            is_ssl = 0
            resp_code = 0
            http_version = 0
        else:
            time_info = resp.time_info
            time_info = self.deal_time_info(time_info)
            content_length = len(resp.body) if resp.body else 0
            is_sucss = str(resp.code) in status_code_list and response_body in resp.text
            is_ssl = resp.effective_url.split('://')[0] == 'https'
            resp_code = resp.code
            http_version = self.response_message.split('\r\n')[0].split(' ')[0].split('/')[1]
        stat = self.return_result_amity(time_info)
        if chart:
            return stat
        output = f"# HELP probe_dns_lookup_time_seconds Returns the time taken for probe dns lookup in seconds\n"\
                 f"# TYPE probe_dns_lookup_time_seconds gauge\n"\
                 f"probe_dns_lookup_time_seconds {time_info['dns_lookup']}\n"\
                 f"# HELP probe_duration_seconds Returns how long the probe took to complete in seconds\n"\
                 f"# TYPE probe_duration_seconds gauge\n"\
                 f"probe_duration_seconds {time_info['total']}\n"\
                 f"# HELP probe_http_content_length Length of http content response\n"\
                 f"# TYPE probe_http_content_length gauge\n"\
                 f"probe_http_content_length {content_length}\n" \
                 f"# Duration of http request by phase, summed over all redirects\n" \
                 f"""probe_http_duration_seconds{'{phase="connect"}'} {time_info["connect"]}\n""" \
                 f"""probe_http_duration_seconds{'{phase="processing"}'} {time_info["server_processing"]}\n""" \
                 f"""probe_http_duration_seconds{'{phase="resolve"}'} {time_info["namelookup"]}\n""" \
                 f"""probe_http_duration_seconds{'{phase="tls"}'} {time_info["tls_handshake"]}\n""" \
                 f"""probe_http_duration_seconds{'{phase="transfer"}'} {time_info["content_transfer"]}\n""" \
                 f"# HELP probe_http_redirects The number of redirects\n" \
                 f"# TYPE probe_http_redirects gauge\n" \
                 f"probe_http_redirects {int(time_info['redirect'])}\n" \
                 f"# HELP probe_http_ssl Indicates if SSL was used for the final redirect\n" \
                 f"# TYPE probe_http_ssl gauge\n" \
                 f"probe_http_ssl {int(is_ssl)}\n" \
                 f"# HELP probe_http_status_code Response HTTP status code\n" \
                 f"# TYPE probe_http_status_code gauge\n" \
                 f"probe_http_status_code {resp_code}\n" \
                 f"# HELP probe_http_version Returns the version of HTTP of the probe response\n" \
                 f"# TYPE probe_http_version gauge\n" \
                 f"probe_http_version {http_version}\n" \
                 f"# HELP probe_success Displays whether or not the probe was a success\n" \
                 f"# TYPE probe_success gauge\n" \
                 f"probe_success {int(is_sucss)}\n"
        return output

    @staticmethod
    def get_urlencoded_body(data: dict) -> Optional[str]:
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
        data = self.get_urlencoded_body(data)
        if method == 'GET':
            body = None
            url = (url + '?' + data) if data else url
        else:
            body = data
        def header_callback(m):
            self.response_message += m
        request = HTTPRequest(
            url, method=method, headers=headers, body=body, request_timeout=timeout,
            connect_timeout=timeout, header_callback=header_callback,
        )
        request.proxy_host = proxy.get('host')
        request.proxy_port = proxy.get('port')
        if proxy.get('proxy_user'):
            request.proxy_username = proxy['proxy_user']
            request.proxy_password = proxy['proxy_pwd']

        if proxy.get('proxy_type') == 'socks5':
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
        try:
            resp = await client.fetch(request, raise_error=False)
            msg = (
                'proxy: {}:{}, url: {} ,result: {}'.format(
                    proxy_dict.get('host'), proxy_dict.get('port'),
                    url, resp.code
                )
            )
            self.logger.debug(msg)
        except Exception as e:
            self.logger.error(
                'proxy: {}:{}, url: {}, result: {}'.format(
                    proxy_dict.get('host'), proxy_dict.get('port'),
                    url, str(e)
                )
            )
            resp = None
        finally:
            client.close()
        if resp:
            resp = self.get_response_body(resp, resp_encoding)
        return resp

    def get_response_body(self, resp: HTTPResponse, resp_encoding: str) -> HTTPResponse:
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
            self.logger.error(content_type)
            return resp_encoding


def main():
    define("addr", default='0.0.0.0', type=str, help="run server on the given address.")  # 定义服务器监听端口选项
    define("port", default=9116, type=int, help="run server on the given port.")  # 定义服务器监听端口选项
    define("log_dir", default="/tmp/network_log", type=str, help="log directory")
    options.parse_config_file('./config')
    options.parse_command_line()
    logger = get_logger(options.log_dir)
    application = Application([
        (r"/probe", MainHandler, {'logger': logger}),
    ])  # 路由规则

    application.listen(options.port, address=options.addr)
    IOLoop.current().start()


if __name__ == "__main__":
    main()
