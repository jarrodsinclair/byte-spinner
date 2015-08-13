import json
import os.path
import unittest

import env
from ByteSpinner import Spinner, SpinnerException


DATA_PATH = os.path.abspath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
)


# to run tests from the repository root directory:
# > python -m unittest discover -s tests -v


class TestKeyGen(unittest.TestCase):
    def test_default(self):
        # default: 256 bytes, 10 iterations
        a = Spinner.generate()
        self.assertEqual(a.get_num_bytes(), 256)
        self.assertEqual(a.get_num_iterations(), 10)

    def test_short(self):
        # 8 bytes, 3 iterations
        a = Spinner.generate(8, 3)
        self.assertEqual(a.get_num_bytes(), 8)
        self.assertEqual(a.get_num_iterations(), 3)

    def test_errors(self):
        # arguments are not integers
        self.assertRaises(SpinnerException, Spinner.generate, 256.1, 10)
        self.assertRaises(SpinnerException, Spinner.generate, 256, 10.1)
        self.assertRaises(SpinnerException, Spinner.generate, 'a', 10)
        self.assertRaises(SpinnerException, Spinner.generate, 256, 'a')

        # arguments are too small
        self.assertRaises(SpinnerException, Spinner.generate, 0, 10)
        self.assertRaises(SpinnerException, Spinner.generate, 256, 0)
        self.assertRaises(SpinnerException, Spinner.generate, -1, 10)
        self.assertRaises(SpinnerException, Spinner.generate, 256, -1)


class TestKeyIO(unittest.TestCase):
    def test_all(self):
        def _do_test(key_name, num_bytes, num_iterations):
            p = os.path.join(DATA_PATH, key_name)
            f = open(p, 'r')
            json_str = f.read()
            f.close()
            m0 = json.dumps(json.loads(json_str), separators=(',', ':'))
            a = Spinner.loads(json_str)
            self.assertEqual(a.get_num_bytes(), num_bytes)
            self.assertEqual(a.get_num_iterations(), num_iterations)
            m1 = json.dumps(json.loads(a.dumps()), separators=(',', ':'))
            self.assertEqual(m0, m1)
        _do_test('key_tiny.json', 4, 1)
        _do_test('key_small.json', 8, 3)
        _do_test('key_recommended.json', 256, 10)


class TestEncDec(unittest.TestCase):
    def test_encdec_new(self):
        # default: 256 bytes, 10 iterations
        a = Spinner.generate()
        pt = bytearray(b'Test string')
        ct = a.encrypt(pt)
        self.assertNotEqual(pt, ct)
        self.assertEqual(len(pt), len(ct))
        pt0 = a.decrypt(ct)
        self.assertEqual(pt, pt0)

    def test_encdec_pre(self):
        # pre-defined key: 256 bytes, 10 iterations
        p = os.path.join(DATA_PATH, 'key_recommended.json')
        f = open(p, 'r')
        json_str = f.read()
        f.close()
        a = Spinner.loads(json_str)
        pt = bytearray(b'abcdABCD')
        ct = a.encrypt(pt)
        self.assertEqual(ct, bytearray([9, 57, 116, 178, 64, 63, 43, 131]))
        self.assertNotEqual(pt, ct)
        self.assertEqual(len(pt), len(ct))
        pt0 = a.decrypt(ct)
        self.assertEqual(pt, pt0)

    def test_lengths(self):
        # 10 bytes, 4 iterations
        a = Spinner.generate(10, 4)

        # ecnryption tests
        a.encrypt(bytearray(b'0123456789'))  # should pass OK
        self.assertRaises(SpinnerException, a.encrypt, bytearray(b'0123456789A'))  # too long
        self.assertRaises(SpinnerException, a.encrypt, bytearray(b''))  # zero length
        self.assertRaises(SpinnerException, a.encrypt, '0123')  # invalid type
        self.assertRaises(SpinnerException, a.encrypt, 1)  # invalid type

        # decryption tests
        a.decrypt(bytearray(b'0123456789'))  # should pass OK
        self.assertRaises(SpinnerException, a.decrypt, bytearray(b'0123456789A'))  # too long
        self.assertRaises(SpinnerException, a.decrypt, bytearray(b''))  # zero length
        self.assertRaises(SpinnerException, a.decrypt, '0123')  # invalid type
        self.assertRaises(SpinnerException, a.decrypt, 1)  # invalid type

    def test_proximity(self):
        # pre-defined key: 256 bytes, 10 iterations
        p = os.path.join(DATA_PATH, 'key_recommended.json')
        f = open(p, 'r')
        json_str = f.read()
        f.close()
        a = Spinner.loads(json_str)
        pt1 = bytearray(b'Test1')
        pt2 = bytearray(b'Test2')
        ct1 = a.encrypt(pt1)
        ct2 = a.encrypt(pt2)

        # check there are no common bytes
        s1 = bytearray_to_set(ct1)
        s2 = bytearray_to_set(ct2)
        num_common = len(s1.intersection(s2))
        self.assertEqual(num_common, 0)


class TestXor(unittest.TestCase):
    def test_simple(self):
        a = Spinner.xor(bytearray([int('0b00000000', 2)]),
                        bytearray([int('0b00000000', 2)]))
        self.assertEqual(a[0],     int('0b00000000', 2))

        a = Spinner.xor(bytearray([int('0b00000000', 2)]),
                        bytearray([int('0b00000001', 2)]))
        self.assertEqual(a[0],     int('0b00000001', 2))

        a = Spinner.xor(bytearray([int('0b00000001', 2)]),
                        bytearray([int('0b00000000', 2)]))
        self.assertEqual(a[0],     int('0b00000001', 2))

        a = Spinner.xor(bytearray([int('0b00000001', 2)]),
                        bytearray([int('0b00000001', 2)]))
        self.assertEqual(a[0],     int('0b00000000', 2))

    def test_multi(self):
        a = Spinner.xor(    bytearray([int('0b10101010', 2), int('0b10010110', 2)]),
                            bytearray([int('0b00000000', 2), int('0b11111111', 2)]))
        self.assertEqual(a, bytearray([int('0b10101010', 2), int('0b01101001', 2)]))

        a = Spinner.xor(    bytearray([int('0b10101010', 2), int('0b10010110', 2)]),
                            bytearray([int('0b11111111', 2), int('0b00000000', 2)]))
        self.assertEqual(a, bytearray([int('0b01010101', 2), int('0b10010110', 2)]))


def bytearray_to_set(b):
    s = set()
    for i in b:
        s.add(i)
    return s


if __name__ == '__main__':
    unittest.main()
