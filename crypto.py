import hashlib

def EVP_BytesToKey(password, key_len, iv_len):
    m = []
    i = 0
    while len(b''.join(m)) < (key_len + iv_len):
        md5 = hashlib.md5()
        data = password
        if i > 0:
            data = m[i - 1] + password
        md5.update(data)
        m.append(md5.digest())
        i += 1
    ms = b''.join(m)
    key = ms[:key_len]
    iv = ms[key_len:key_len + iv_len]
    return key, iv

class BaseCipher(object):
    KEY_LEN = 0
    IV_LEN = 0

    def __init__(self, passwd):
        from Crypto import Random
        if hasattr(passwd, 'encode'):
            passwd = passwd.encode('utf-8')
        self._key, _ = EVP_BytesToKey(passwd, self.KEY_LEN, self.IV_LEN)
        self._iv = Random.get_random_bytes(self.IV_LEN)
        self._first_package = True
        self._cipher = None

    def setup(self, key, iv):
        return NotImplemented

    def encrypt(self, data):
        if self._first_package:
            self._first_package = False
            self.setup(self._key, self._iv)
            return self._iv + self._cipher.encrypt(data)
        return self._cipher.encrypt(data)

    def decrypt(self, data):
        if self._first_package:
            self._first_package = False
            if len(data) < self.IV_LEN:
                return b''
            self.setup(self._key, data[:self.IV_LEN])
            return self._cipher.decrypt(data[self.IV_LEN:])
        return self._cipher.decrypt(data)

class ChaCha20_Cipher(BaseCipher):
    KEY_LEN = 32
    IV_LEN = 8
    def setup(self, key, iv):
        from Crypto.Cipher import ChaCha20
        self._cipher = ChaCha20.new(key=key, nonce=iv)

mappings = {'chacha20': ChaCha20_Cipher}

def get_cipher(method, passwd):
    cipher = mappings[method.lower()]
    return cipher(passwd)


if __name__ == '__main__':
    text = b'this is a text'
    passwd = b'hello'
    cipher = ChaCha20_Cipher(passwd)
    ctext = cipher.encrypt(text)
    print(ctext)
    cipher = ChaCha20_Cipher(passwd)
    mtext = cipher.decrypt(ctext)
    print(mtext)