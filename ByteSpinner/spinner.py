import base64
from Crypto import Random
import json


class SpinnerException(Exception):
    pass


class Spinner(object):
    def __init__(self, key_matrix):
        self._keys = key_matrix

        # check key matrix is well formed
        num_iterations = len(self._keys)
        assert num_iterations > 0
        num_bytes = len(self._keys[0][0])
        assert num_bytes > 0
        for local_keys in self._keys:
            assert len(local_keys) == 256
            for key in local_keys:
                assert len(key) == num_bytes

    @classmethod
    def generate(cls, num_bytes=256, num_iterations=10):
        # explicitly check inputs
        if not isinstance(num_bytes, int):
            raise SpinnerException('Number of bytes must be an integer.')
        if not isinstance(num_iterations, int):
            raise SpinnerException('Number of iterations must be an integer.')
        if num_bytes <= 0:
            raise SpinnerException('Number of bytes must be positive.')
        if num_iterations <= 0:
            raise SpinnerException('Number of iterations must be positive.')

        # create matrix of new keys
        m = []
        for i in range(num_iterations):
            n = []
            for c in range(256):
                n.append(bytearray(Random.get_random_bytes(num_bytes)))
            m.append(n)

        # create and return object
        return cls(m)

    @classmethod
    def loads(cls, s):
        # load json string into dictionary
        j = json.loads(s)

        # verify dictionary model, build matrix of keys
        m = []
        assert 'keys' in j
        assert isinstance(j['keys'], list)
        num_iters = len(j['keys'])
        assert num_iters > 0
        first = True
        num_bytes = 0
        for i in j['keys']:
            assert isinstance(i, list)
            assert len(i) == 256
            m_local = []
            for c in i:
                b = bytearray(base64.b64decode(c))
                if first:
                    num_bytes = len(b)
                    assert num_bytes > 0
                    first = False
                else:
                    assert len(b) == num_bytes
                m_local.append(b)
            m.append(m_local)

        # create and return object
        return cls(m)

    def dumps(self):
        s = '{\n    "keys": [\n'
        outer_first = True
        for local_keys in self._keys:
            if not outer_first:
                s += ',\n'
            outer_first = False
            s += '        [\n'
            inner_first = True
            for key in local_keys:
                if not inner_first:
                    s += ',\n'
                inner_first = False
                s += '            "%s"' % base64.b64encode(key).decode('utf-8')
            s += '\n        ]'
        s += '\n    ]\n}'
        return s

    @property
    def num_bytes(self):
        return len(self._keys[0][0])

    @property
    def num_iterations(self):
        return len(self._keys)

    def encrypt(self, plaintext):
        # explicitly check plaintext before use
        if not isinstance(plaintext, bytearray):
            raise SpinnerException('Plaintext must be a bytearray.')
        num_pt_bytes = len(plaintext)
        if num_pt_bytes <= 0:
            raise SpinnerException('Plaintext is zero length.')
        if num_pt_bytes > self.num_bytes:
            raise SpinnerException('Plaintext is too long.')

        # do encryption
        ct = plaintext
        num_iterations = self.num_iterations
        for itr in range(num_iterations):
            for pos in range(num_pt_bytes):
                b = ct[pos]
                assert (b >= 0 and b <= 255)
                ct = self.xor(ct, self._keys[itr][b])
                ct[pos] = b
        return ct

    def decrypt(self, ciphertext):
        # explicitly check ciphertext before use
        if not isinstance(ciphertext, bytearray):
            raise SpinnerException('Ciphertext must be a bytearray.')
        num_ct_bytes = len(ciphertext)
        if num_ct_bytes <= 0:
            raise SpinnerException('Ciphertext is zero length.')
        if num_ct_bytes > self.num_bytes:
            raise SpinnerException('Ciphertext is too long.')

        # do decryption
        pt = ciphertext
        num_iterations = self.num_iterations
        for itr in range(num_iterations-1, -1, -1):
            for pos in range(num_ct_bytes-1, -1, -1):
                b = pt[pos]
                assert (b >= 0 and b <= 255)
                pt = self.xor(pt, self._keys[itr][b])
                pt[pos] = b
        return pt

    @staticmethod
    def xor(a, b):
        assert isinstance(a, bytearray)
        assert isinstance(b, bytearray)
        num_bytes = len(a)
        assert num_bytes <= len(b)
        ret = bytearray()
        for i in range(num_bytes):
            ret.append(a[i] ^ b[i])
        return ret
