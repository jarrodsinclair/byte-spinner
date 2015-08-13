ByteSpinner
===========

A Python library and command-line utility to encrypt short plaintext bytes using
an enhanced XOR algorithm.

Usage in Python
---------------

Generating a new key and testing the encryption:

```python
from ByteSpinner import Spinner

# generate new symmetric key, write to file
sp = Spinner.generate()
f = open('my_secret_key.json', 'w')
f.write(sp.dumps())
f.close()

# encrypt some text
plaintext = bytearray(b'Testing ByteSpinner encryption.')
ciphertext = sp.encrypt(plaintext)
assert plaintext != ciphertext

# decrypt and check
plaintext_check = sp.decrypt(ciphertext)
assert plaintext == plaintext_check
```

Reading the key and displaying the properties:

```python
from ByteSpinner import Spinner

# read previous key
f = open('my_secret_key.json', 'r')
sp = Spinner.loads(f.read())
f.close()

# print properties
print('XOR base length: %d' % sp.get_num_bytes())
print('Iterations: %d' % sp.get_num_iterations())
```

Usage on the command line
-------------------------

Generating a new key:

```shell
bytespinner gen my_secret_key.json
```

Show key properties:

```shell
bytespinner info my_secret_key.json
```

Encrypt a plaintext file:

```shell
echo "Testing ByteSpinner encryption." > plaintext.txt
bytespinner enc my_secret_key.json plaintext.txt ciphertext.out
```

Decrypt back to plaintext and check the result:

```shell
bytespinner dec my_secret_key.json ciphertext.out plaintext_check.txt
diff plaintext.txt plaintext_check.txt
```
