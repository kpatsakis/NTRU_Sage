NTRU_Sage
=========
Yet another NTRU implementation, this time in Sage...
-----------------------------------------------------

For those using Sage (http://www.sagemath.org/) and want to start playing around with lattice-based encryption. The code implements the well-known NTRU encryption algorithm. Since it's Sage don't expect the actual performance of NTRU, but it is fairly decent. The code uses the latest specs of the algorithm as defined by SecurityInnovation (https://securityinnovation.com/). If you are looking for performance try here https://github.com/NTRUOpenSourceProject/ntru-crypto.

Usage
-----

The library is very straight forward. On initialization choose your security level (128, 192 or 256) and then call `gen_keys()` to generate the public/private key pair.
The latter will return `h` and `f`, `fp`. To encypt a message, simply use the `encrypt` method, providing the message `m` and the public key of the recipient `h`. Similarly, to decrypt a message, use the `decrypt` method providing the ciphertext and the private key.

The provided code illustrates the class usage, performance and the additive homomorphic property of NTRU.
