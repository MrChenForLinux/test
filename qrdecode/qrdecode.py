import ybc_config
import requests
import os
import sys
from ybc_exception import *

__PREFIX = ybc_config.config['prefix']
__QRDECODE_URL = __PREFIX + ybc_config.uri + '/qrcode'


def decode(filename=''):
    """
    识别二维码
    :param filename: 待识别的图片
    :return: 识别结果信息
    """
    if not isinstance(filename, str):
        raise ParameterTypeError(sys._getframe().f_code.co_name, "'filename'")
    if filename == '':
        raise ParameterValueError(sys._getframe().f_code.co_name, "'filename'")
    try:
        url = __QRDECODE_URL
        filepath = os.path.abspath(filename)
        files = {}
        with open(filepath, 'rb') as fp:
            files['file'] = fp.read()

        for i in range(3):
            r = requests.post(url, files=files)
            if r.status_code == 200:
                return r.text

        return '没有识别出二维码'

    except Exception as e:
        raise InternalError(e, 'qrdecode')


def main():
    print(decode('D:\Projects\hc1_verify\photo1.jpg'))
    #print(decode('test2.jpg'))


if __name__ == '__main__':
    main()
