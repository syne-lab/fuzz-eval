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

ADD https://github.com/openssl/openssl/archive/c74188e86c78c4fa47c4a658e1355c40524fadb4.zip?raw=true /target/openssl-c74188e.zip






COPY ./pkcs_grammar.py /target/pkcs_grammar.py
COPY ./pkcs_template.xml /target/pkcs_template.xml
COPY ./config.ron /target/config.ron
WORKDIR /FC

CMD ./build-then-fuzz.sh