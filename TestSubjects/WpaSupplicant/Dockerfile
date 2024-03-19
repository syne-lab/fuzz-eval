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
ADD https://w1.fi/releases/wpa_supplicant-2.9.tar.gz?raw=true /target/wpa_supplicant-2.9.tar.gz




RUN apt-get install -y libnl-3-dev libnl-genl-3-dev libreadline-dev 








COPY ./pkcs_grammar.py /target/pkcs_grammar.py
COPY ./pkcs_template.xml /target/pkcs_template.xml
COPY ./config.ron /target/config.ron
# Setting up the target
WORKDIR /FC
CMD ./build-then-fuzz.sh