### Formally Verified Implementation of PKCS1 v1.5

This document explains how we can extract an executable binary of PKCS1 v1.5 signature verification from a formally verified code in Coq and shows how you can run the binary file against some notorious testcases, crafted from previous work (NDSS'19). The testcases results show it can succesfully parse/verify them to be invalid (what else would you expect? It's fromally verified!)

#### Installing coq and check the proofs by yourself

If you only want compile the oracle, you do not have to read this section and can jump into **Compile the oracle**.

The `pkcs1.v` file contains formally verified code in Coq. So, to compile that we need to install Coq first. To do that, please follow
the instruction at [https://coq.inria.fr/opam-using.html](https://coq.inria.fr/opam-using.html).

The current proof work has been done using the following version:

```
$ coqc -v

The Coq Proof Assistant, version 8.12.0 (August 2020)
compiled on Aug 26 2020 18:38:48 with OCaml 4.07.1
```

If you are using newer versions, it should be fine as well.

After installing Coq, you need to install some mathematical components using the following commands (See [this](https://math-comp.github.io/installation.html) for more details):

```
$ opam repo add coq-released https://coq.inria.fr/opam/released
$ opam install coq-mathcomp-ssreflect
```

**Side note**: If you want to check the proofs line by line using a GUI, please install `coqide` using instruction at [https://coq.inria.fr/opam-using.html](https://coq.inria.fr/opam-using.html). 

At the end of `pkcs1.v` file, there is `Extraction` vernacular command that spits out an Ocaml translation of `pkcs1.v`'s computation code.

To compile the `pkcs1.v`, use coq compiler by running: 

```
$ coqc pkcs1.v
```

which spits out `pkcs1.ml` Ocaml file and its interface file `pkcs.mli`. 

#### Compile the oracle

As mentioned before, you do not have to compile `pkcs1.v` coq file to get its Ocaml translated version out because `pkcs1.ml` is also maintained in this repo.

In order to have a final oracle product, there need to be some driver code that wraps around `signature_verificaion` function of `pkcs1.ml` and takes input from the command line interface to be passed to that function. This driver code exists in `oracle.ml` file. So, in order to get the oracle executable binary, we have to combile it using `ocamlc` compiler by running:

``` 
$ ocamlc -o oracle pkcs1.mli pkcs1.ml oracle.ml
```

which creates `oracle` binary file.

To run the `oracle`, you should use the following command:

```
$ ./oracle <input_buffer> <public_modulus_length> <hash_value> <hash_algorithm_name>
```

where `<input_buffer>` is the list of bytes in hex form (without initial `0x`) that represents the structure obtained after taking modular exponentiation of public exponent `e`; `<public_modulus_length>` is a number that represents the length of public modulus `n`; `<hash_value>` is the list of bytes in hex form (without initial `0x`) that represents the hash value; and finally `<hash_algorithm_name>` that represents the hash function used for signing which can be one of the following `1`, `224`, `256`, `384`, and `512` identifiers related to `sha1`, `sha224`, `sha256`, `sha384`, and `sha512`, respectively. 

Once executed, `oracle` returns either `ture` if the signature verification is passed or `false` otherwise.

#### Some sample useful testcases for PKCS1v1.5 signature verification

These testcases are borrowd from the previous work. In these testcases we use, `|n|= 512 bits`, `H() = sha256`, and `m = "hello world"`. 

Given that, we have:

```
H(m)= b9 4d 27 b9 93 4d 3e 08 a5 2e 52 d7 da 7d ab fa c4 84 ef e3 7a 53 80 ee 90 88 f7 ac e2 ef cd e9
the encoded TLV of the OID of H()= 06 09 60 86 48 01 65 03 04 02 01
```



##### Correct structure

Thus the correct pading structure should look like this:

```
00 01 ff ff ff ff ff ff ff ff ff ff 00 30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20 
b9 4d 27 b9 93 4d 3e 08 a5 2e 52 d7 da 7d ab fa c4 84 ef e3 7a 53 80 ee 90 88 f7 ac e2 ef cd e9
```

which you can verify using the below command:

```
$ ./oracle 0001ffffffffffffffffffff003031300d060960864801650304020105000420b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9 64 b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9 256

true
```

the last line `true` is the result of executing `oracle` against those arguments.


##### Invalid structures

Not rejecting garbage null algorithm parameters
  

```
00 01 ff ff ff ff ff ff ff ff 00 30 33 30 0f 06 09 60 86 48 01 65 03 04 02 01 05 02 01 01 04 20 
b9 4d 27 b9 93 4d 3e 08 a5 2e 52 d7 da 7d ab fa c4 84 ef e3 7a 53 80 ee 90 88 f7 ac e2 ef cd e9
```

which you can verify to be `false` using the following command:


```
$ ./oracle 0001ffffffffffffffff003033300f0609608648016503040201050201010420b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9 64 b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9 256
  
false
```

-----

Not rejecting trailing bytes after OID

```
00 01 ff ff ff ff ff ff ff ff 00 30 33 30 0f 06 0b 60 86 48 01 65 03 04 02 01 01 01 05 00 04 20 
b9 4d 27 b9 93 4d 3e 08 a5 2e 52 d7 da 7d ab fa c4 84 ef e3 7a 53 80 ee 90 88 f7 ac e2 ef cd e9
```

which you can verify to be `false` using the following command:


```
$ ./oracle 0001ffffffffffffffff003033300f060b608648016503040201010105000420b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9 64 b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9 256

false
```

-----

1st byte is wrong (should be 00 , not 01 ), wrong padding bytes (should be ff , not 01 ), plus 2 bytes of trailing garbage after hash (the 2 bytes of 01 01 at the end)


```
01 01 01 01 01 01 01 01 01 01 00 30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20 b9 4d 
27 b9 93 4d 3e 08 a5 2e 52 d7 da 7d ab fa c4 84 ef e3 7a 53 80 ee 90 88 f7 ac e2 ef cd e9 01 01
```

which you can verify to be `false` using the following command:


```
$ ./oracle 01010101010101010101003031300d060960864801650304020105000420b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde90101 64 b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9 256

false
```

-----

1st byte is wrong (should be 00 , not 01 ), 2nd byte is wrong (should be 01 , not 00 ), wrong padding bytes (should be ff , not 01 ), plus 2 bytes of trailing garbage after hash (the 2 bytes of 01 01 at the end)

  
```
01 00 01 01 01 01 01 01 01 01 00 30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20 b9 4d 
27 b9 93 4d 3e 08 a5 2e 52 d7 da 7d ab fa c4 84 ef e3 7a 53 80 ee 90 88 f7 ac e2 ef cd e9 01 01
```

which you can verify to be `false` using the following command:


```
$ ./oracle 01000101010101010101003031300d060960864801650304020105000420b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde90101 64 b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9 256

false
```

-----

wrong padding bytes (should be ff , not 01 ), plus 2 bytes of trailing garbage after hash (the 2 bytes of 01 01 at the end)


```
00 01 01 01 01 01 01 01 01 01 00 30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20 b9 4d 
27 b9 93 4d 3e 08 a5 2e 52 d7 da 7d ab fa c4 84 ef e3 7a 53 80 ee 90 88 f7 ac e2 ef cd e9 00 00
```

which you can verify to be `false` using the following command:


```
$ ./oracle 00010101010101010101003031300d060960864801650304020105000420b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde90000 64 b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9 256

false
```

-----

2nd byte is wrong (should be 01 , not 02 ), wrong padding bytes (should be ff , not 01 ), plus 2 bytes of trailing garbage after hash (the 2 bytes of 01 01 at the end)


```
00 02 01 01 01 01 01 01 01 01 00 30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20 b9 4d 
27 b9 93 4d 3e 08 a5 2e 52 d7 da 7d ab fa c4 84 ef e3 7a 53 80 ee 90 88 f7 ac e2 ef cd e9 00 00
```

which you can verify to be `false` using the following command:

  
```
$ ./oracle 00020101010101010101003031300d060960864801650304020105000420b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde90000 64 b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9 256

false
```

-----

2nd byte is wrong (should be 01 , not 00 ), wrong padding bytes (should be ff , not 01 ), plus 2 bytes of trailing garbage after hash (the 2 bytes of 01 01 at the end)

  
```
00 00 01 01 01 01 01 01 01 01 00 30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20 b9 4d 
27 b9 93 4d 3e 08 a5 2e 52 d7 da 7d ab fa c4 84 ef e3 7a 53 80 ee 90 88 f7 ac e2 ef cd e9 00 00
```
 
which you can verify to be `false` using the following command:

  
```
$ ./oracle 00000101010101010101003031300d060960864801650304020105000420b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde90000 64 b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9 256
  
false
```

  

