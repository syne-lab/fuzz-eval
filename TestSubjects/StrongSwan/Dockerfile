ARG baseimage
FROM $baseimage

ARG fc_configpath
ENV CONFIGPATH=$fc_configpath


COPY ./fcbuilder.sh /FC/fcbuilder.sh
RUN chmod +x /FC/fcbuilder.sh

COPY ./fcrunner.sh /FC/fcrunner.sh
RUN chmod +x /FC/fcrunner.sh

COPY ./build-then-fuzz.sh /FC/build-then-fuzz.sh
RUN chmod +x /FC/build-then-fuzz.sh

ARG harness_dir
COPY ./${harness_dir}/ /target
ADD https://download.strongswan.org/old/5.x/strongswan-5.9.2.tar.bz2?raw=true /target/strongswan-5.9.2.tar.bz2
ADD https://gmplib.org/download/gmp/gmp-6.1.2.tar.xz?raw=true /target/gmp-6.1.2.tar.xz
RUN  apt-get -y install m4 libgmp-dev gperf









COPY ./pkcs_grammar.py /target/pkcs_grammar.py
COPY ./pkcs_template.xml /target/pkcs_template.xml
COPY ./config.ron /target/config.ron
# Setting up the target
WORKDIR /FC

CMD ./build-then-fuzz.sh