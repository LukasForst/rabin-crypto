# Rabin cryptosystem
Implementation of Rabin cryptosystem according to [Wikipedia](https://en.wikipedia.org/wiki/Rabin_cryptosystem) 
specification.

The Rabin cryptosystem has a property, that it produces four different plaintexts 
after the decryption and it is not specified, how to choose the correct one.

There are multiple padding strategies implemented in the package `rabin.padding`,
 one can choose the best suiting one.
 
There are some tests in the `main.py`, feel free to explore.