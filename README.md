# libcgc

Liphium's encryption primitives for containerizing information sent to the server.

## Security

LibCGC has never been audited, but it's using industry-standard libraries for most of its cryptography implementations. However, some cryptographic primitives libcgc uses have not been audited yet. Namely, RustCrypto's [x-wing](https://github.com/RustCrypto/KEMs/tree/master/x-wing) and RustCrypto's [ml-dsa](https://github.com/RustCrypto/signatures/tree/master/ml-dsa). 

However, those primitives are only used to provide quantum-resistant encryption. Part of x-wing uses a well-tested and audited ecliptic curves implementation meaning it's at least resistant to normal attack vectors (at least it should be, an audit of the implementation would still be good). That's why we're already using it in Liphium.

USE AT YOUR OWN RISK.