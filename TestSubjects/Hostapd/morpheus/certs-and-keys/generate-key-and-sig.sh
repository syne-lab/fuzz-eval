openssl genrsa -3 -out ca-priv-key 2048
openssl req -key ca-priv-key -new -out ca.csr
openssl x509 -signkey ca-priv-key -in ca.csr -req -days 365 -out ca.crt
openssl x509 -in ca.crt -inform PEM -out ca.der -outform DER
# printf "You know, factorization breaks RSA." | openssl rsautl -sign -inkey ./ca-priv-key -out ca-sig
printf "You know, factorization breaks RSA." | openssl dgst -sha1 -sign ca-priv-key -out ca-sig

openssl rsa -in ca-priv-key -inform PEM -noout -text -modulus

xxd -i ca.der
xxd -i ca-sig

