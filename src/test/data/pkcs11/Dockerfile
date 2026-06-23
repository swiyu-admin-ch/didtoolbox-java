FROM --platform=linux/amd64 maven:3.9-eclipse-temurin-26-noble
COPY libs /usr/lib/x86_64-linux-gnu/softhsm/
COPY tokens /tokens
COPY config /config
COPY bins /bins/

RUN chmod 777 -R /tokens

ENV SOFTHSM2_CONF=/config/softhsm.conf
ENV HSM_LIBRARY=/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so
ENV LD_LIBRARY_PATH=/usr/lib/x86_64-linux-gnu/softhsm/
ENV PKCS11_TEST=true
RUN useradd -m -s /bin/bash mvn
RUN apt update && apt install libglib2.0-dev opensc-pkcs11 -y
USER mvn

WORKDIR /bins
RUN ./softhsm2-util \
    --init-token \
    --free \
    --label "token" \
    --pin "secret" \
    --so-pin "secret"

RUN ./softhsm2-util \
    --module "${HSM_LIBRARY}" \
    --token "token" \
    --label "1111" \
    --id "1111" \
    --import "/tokens/private-key.pem" \
    --pin "secret"

RUN ./pkcs11-tool \
    --module "${HSM_LIBRARY}" \
    --login \
    --pin "secret" \
    --token-label "token" \
    --write-object "/tokens/private-key.cert" \
    --type cert \
    --label "1111" \
    --id "1111"
WORKDIR /app
