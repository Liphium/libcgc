# libcgc

Liphium's encryption primitives for containerizing information sent to the server. CGC stands for (C)rypto(G)raphic (C)ontainers. This library provides you with two containers (maybe more in the future): ``auth_asymmetric`` and ``auth_symmetric``. Both contain a signature (hence the ``auth`` prefix) to make sure you're actually decrypting the message from the sender you think you are. You can also attach a salt to prevent replay attacks. In Liphium (our chat app), for example, we attach message timestamps as salts to prevent the message from being sent again by someone pretending to be you. Time modifications could significantly change the context of the sent message and it's something you would want to avoid in all cases where stuff is being encrypted.

Documentation and how to use the library will follow at a later date. We will first verify the usefulness of libcgc in the real world ourselves.

LibCGC is available [here](https://crates.io/crates/libcgc) on the crates.io repository. Add it to your project by using the following command:
```
cargo add libcgc
```

## Security

LibCGC has never been audited, but it's using industry-standard libraries for most of its cryptography implementations. However, some cryptographic primitives libcgc uses have not been audited yet. Namely, RustCrypto's [x-wing](https://github.com/RustCrypto/KEMs/tree/master/x-wing) and RustCrypto's [ml-dsa](https://github.com/RustCrypto/signatures/tree/master/ml-dsa). 

However, those primitives are only used to provide quantum-resistant encryption. Part of x-wing uses a well-tested and audited ecliptic curves implementation meaning it's at least resistant to normal attack vectors (at least it should be, an audit of the implementation would still be good). That's why we're already using it in Liphium.

USE AT YOUR OWN RISK.
