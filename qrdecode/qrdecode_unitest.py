import unittest
from qrdecode import *


path_pic1 = os.path.join(os.path.split(os.path.abspath(__file__))[0], 'test1.jpg')
path_pic2 = os.path.join(os.path.split(os.path.abspath(__file__))[0], 'test2.jpg')


class MyTestCase(unittest.TestCase):
    def test_qrdecode1(self):
        self.assertEqual('https://www.yuanfudao.com/download?userType=student&vendor=&keyfrom=', decode(path_pic1))

    def test_qrdecode2(self):
        self.assertEqual('没有识别出二维码', decode(path_pic2))

    def test_qrdecode_ParameterTypeError(self):
        with self.assertRaisesRegex(ParameterTypeError, "^参数类型错误 : 调用decode方法时，'filename'参数类型错误。$"):
            decode(1)

    def test_qrdecode_ParameterValueError(self):
        with self.assertRaisesRegex(ParameterValueError, "^参数数值错误 : 调用decode方法时，'filename'参数不在允许范围内。$"):
            decode('')


if __name__ == '__main__':
    unittest.main()
