# Rabin cryptosystem
Implementation of Rabin cryptosystem according to [Wikipedia](https://en.wikipedia.org/wiki/Rabin_cryptosystem) 
specification.

The Rabin cryptosystem has a property, that it produces four different plaintexts 
after the decryption and it is not specified, how to choose the correct one.

There are multiple padding strategies implemented in the package `rabin.padding`,
 one can choose the best suiting one.
 
There are some tests in the `main.py`, feel free to explore.

## Execution

The best way how to test the cryptosystem is to simply run `python main.py` which contains all the test.
However, to do so, one must have [PyCryptodome](https://pycryptodome.readthedocs.io/en/latest/)
and possibly other dependencies installed, see the following sections. 

### Requirements
Ideally [Conda](https://docs.conda.io/en/latest/), but it is not neccessary, see following sections.

#### Using Conda
The Conda has the advantage that it will set the environment for you. 
In theory, the execution environment should be completely the same as it was during the development.

* run `make conda-create` - this creates conda environment
* run `conda activate rabin-crypto` - this activates conda environment for your current shell

#### Without Conda
The rabin cryptosystem was developed and tested on Python 3.8.3, but we suppose that it should 
work with older pythons >= 3.6 as well. 

The program uses a single external dependency [PyCryptodome](https://pycryptodome.readthedocs.io/en/latest/)
to generate cryptographically secure prime numbers and for other operations. 
For that reason one must install have it installed, the simpliest way how to do it is to use `pip`
```bash
pip install pycryptodome
```

