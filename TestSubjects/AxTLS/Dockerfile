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
ADD https://sourceforge.net/projects/axtls/files/2.1.5/axTLS-2.1.5.tar.gz/download /target/axTLS-2.1.5.tar.gz



COPY ./entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
COPY ./pkcs_grammar.py /target/pkcs_grammar.py
COPY ./pkcs_template.xml /target/pkcs_template.xml
COPY ./config.ron /target/config.ron
# Setting up the target
WORKDIR /FC
ENTRYPOINT [ "/entrypoint.sh" ]

CMD ./build-then-fuzz.sh