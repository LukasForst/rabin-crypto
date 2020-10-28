# Rabin cryptosystem
Implementation of Rabin cryptosystem according to [this](https://en.wikipedia.org/wiki/Rabin_cryptosystem) 
specification.

The Rabin cryptosystem has a property, that it produces four different plaintexts 
after the decryption and it is not specified, how to choose the correct one.

## Disambiguation problem
We implemented two different strategies solving the disambiguation problem.
The idea behind all strategies is to append some additional padding, 
which is then present after the decryption. 
Then the algorithm verifies which one of the four plaintexts have the correct padding
and chooses the one with the correct one.

This approach reduces the size of the number that can be encrypted, but it solves the disambiguation problem.
The benchmarks showed that appending `16` bits is enough to distinguish between the produced plaintexts.

The strategies are implemented in package `rabin.padding`.

### Padding with bits repetition
Implemented in [CopyBitsStrategy](rabin/padding/copy_bits_strategy.py), 
this strategy takes last `X` bits from the original number, copies them and appends them 
at the end of the number.
This was inspired by the [following implementation](https://github.com/duckbill360/Rabin-Public-Key-Cryptosystem/blob/master/Rabin.py#L13).

This strategy has a downside that it limits the smallest number the algorithm can encrypt
as it needs at least `X` bit number.
On the other hand, it is not necessary to remember the padding.

### Static padding
Implemented in [FixedPaddingBitsStrategy](rabin/padding/fixed_padding_bits_strategy.py), 
this strategy uses static padding which is appended at the end of the number before the encryption.
The advantage is that one can encrypt as small number as 1 bit, but needs to remember the padding used.

In the class [FileRabinCryptosystem](rabin/cryptosystem/file.py), the problem of remembering the padding
is solved by prepending the padding at the beginning of the encrypted file.
During the file decryption, the program reads the padding first and initializes the padding strategy.


## Generating the keys
The implementation uses [PyCryptodome](https://pycryptodome.readthedocs.io/en/latest/) as a convenient
wrapper around OS cryptography to generate cryptographically secure prime numbers and for other operations.
The library internally uses `urandom` which has following description. 
```python
def urandom(*args, **kwargs): # real signature unknown
    """ Return a bytes object containing random bytes suitable for cryptographic use. """
    pass
```
Thus, the generated keys use cryptographically secure random bits generator.

### Not using external libraries
We could have implemented it without [PyCryptodome](https://pycryptodome.readthedocs.io/en/latest/)
 by directly using `urandom` and then finding prime numbers for example using Miller-Rabin primality test.
However, we think that it is simply easier, to let widely used opensource library do the heavy lifting.
Of course, we did a research before using the library and explored the code in order to verify,
what it actually does. 

## Execution

The best way how to test the cryptosystem is to simply run `python main.py` which contains all the test.
However, to do so, one must have [PyCryptodome](https://pycryptodome.readthedocs.io/en/latest/)
and possibly other dependencies installed, see the following sections. 

### Requirements
Ideally [Conda](https://docs.conda.io/en/latest/), but it is not necessary, see following sections.

#### Using Conda
The Conda has the advantage that it will set the environment for you. 
In theory, the execution environment should be completely the same as it was during the development.

* run `make conda-create` - this creates conda environment
* run `conda activate rabin-crypto` - this activates conda environment for your current shell

#### Without Conda
The rabin cryptosystem was developed and tested on Python 3.8.3, but we suppose that it should 
work with older pythons >= 3.6 as well. 

The program uses a single external dependency [PyCryptodome](https://pycryptodome.readthedocs.io/en/latest/).
For that reason one must install have it installed, the simpliest way how to do it is to use `pip`
```bash
pip install pycryptodome
```

