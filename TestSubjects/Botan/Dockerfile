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
ADD https://botan.randombit.net/releases/Botan-2.17.3.tar.xz?raw=true /target/Botan-2.17.3.tar.xz






COPY ./pkcs_grammar.py /target/pkcs_grammar.py
COPY ./pkcs_template.xml /target/pkcs_template.xml
COPY ./config.ron /target/config.ron


WORKDIR /FC

CMD ./build-then-fuzz.sh