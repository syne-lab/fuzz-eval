ARG baseimage
FROM $baseimage
RUN apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 15CF4D18AF4F7421
RUN apt-get update -y
RUN apt-get upgrade -y

RUN pip3.10 install isla-solver
COPY ./fuzz_goat.py /isla/fuzz_goat.py
COPY ./pkcs-cons-2.isla /isla/pkcs-cons.isla
COPY ./pkcs.bnf /isla/pkcs.bnf
COPY ./run_fuzz.sh /isla/run_fuzz.sh
RUN chmod +x /isla/run_fuzz.sh

WORKDIR /isla
CMD ["/isla/run_fuzz.sh", "100"]