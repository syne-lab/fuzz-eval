#### Warning

- if I understand correctly, Openswan only supports SHA1 signatures but not SHA256

#### how to run

- first run `build-openswan.sh`

- then `cd test-harness` and run `make`

- then run `./pkcs1 <signature-hex-string>` (make sure the signature uses SHA1, not SHA256), e.g. try `./pkcs1 1722185a66e725736f07b1e14b6072b375b9382ec60c2179a330124763710eebae92dde3a42d9cdb7eb2dbb21825581d2e39fb2adac58e0687c95bd84364175fb65804a91f68beabfcff1ae820b4000151cd99f751838e71c03576696f2ba4405270c6207c1257bdd9067362ff761e96f3098f2589af871dfbf1b8ec0946744a00918aa1fe27b90134a33cb1e832ae9d79ac582a8f13658fd7764b9d8420f8af8d45fdfde3e46f71c8bd3dc7a3c30054c74590454d91bb735d707944f5db72204be734658aea69b6856f342ba32f96daddb95d1a2e93fc94ce33a67e8a7e92fe679fe1e2fe9f07906924aeef2df762b121bc08e47ffcfcbd60e3564eedee3e45` and you should get `ret = 0`
