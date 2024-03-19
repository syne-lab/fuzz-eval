ARG baseimage
FROM $baseimage

ARG fc_configpath
ENV CONFIGPATH=$fc_configpath
# Copy build and runner scripts
COPY ./fcbuilder.sh /FC/fcbuilder.sh
RUN chmod +x /FC/fcbuilder.sh
COPY ./fcrunner.sh /FC/fcrunner.sh
RUN chmod +x /FC/fcrunner.sh
COPY ./build-then-fuzz.sh /FC/build-then-fuzz.sh
RUN chmod +x /FC/build-then-fuzz.sh

# Copy the target and download the source
ARG harness_dir
COPY ./${harness_dir}/ /target

ADD https://gmplib.org/download/gmp/gmp-6.1.2.tar.xz?raw=true /target/gmp-6.1.2.tar.xz
ADD https://ftp.gnu.org/gnu/nettle/nettle-3.7.2.tar.gz?raw=true /target/nettle-3.7.2.tar.gz
ADD https://www.gnupg.org/ftp/gcrypt/gnutls/v3.6/gnutls-3.6.15.tar.xz?raw=true /target/gnutls-3.6.15.tar.xz

RUN apt-get install m4 -y

COPY ./pkcs_grammar.py /target/pkcs_grammar.py
COPY ./pkcs_template.xml /target/pkcs_template.xml
COPY ./config.ron /target/config.ron
WORKDIR /FC

CMD ./build-then-fuzz.sh