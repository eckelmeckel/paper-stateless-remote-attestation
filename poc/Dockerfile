FROM alpine:latest AS base

ARG user='me'
ARG uid=1000
ARG gid=1000

ARG mbedtls_version='v3.6.4'
ARG mbedtls_git_url='https://github.com/ARMmbed/mbedtls'
ARG mbedtls_tmp_dir='/tmp/mbedtls'


## -----------------------------------------------------------------------------
## --- install software --------------------------------------------------------
## -----------------------------------------------------------------------------

## install dependencies
RUN apk add --update --no-cache \
    build-base \
    && rm -rf /var/cache/apk/*


## mbed TLS
RUN apk add --update --no-cache \
    git \
    && rm -rf /var/cache/apk/*
RUN apk add --update --no-cache \
    build-base \
    gcc \
    make \
    perl \
    py3-jinja2 \
    py3-jsonschema \
    && rm -rf /var/cache/apk/*
RUN git clone --depth=1 --recursive -b "${mbedtls_version}" \
    "${mbedtls_git_url}" \
    "${mbedtls_tmp_dir}"
WORKDIR "${mbedtls_tmp_dir}"
RUN git reset --hard \
    && git clean -xdf \
    && make -j lib SHARED=true \
    && make install
WORKDIR /
RUN rm -rfv "${mbedtls_tmp_dir}"


## -----------------------------------------------------------------------------
## --- setup user --------------------------------------------------------------
## -----------------------------------------------------------------------------

## install sudo
RUN apk add --update --no-cache \
    sudo \
    && rm -rf /var/cache/apk/*

## create non-root user and grant sudo permission
RUN addgroup -g "${gid}" "${user}" \
    && adduser -h /home/"${user}" -u "${uid}" -G "${user}" \
    -s /bin/bash -D -g '' "${user}" \
    && mkdir -vp /etc/sudoers.d/ \
    && echo "${user}     ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/"${user}" \
    && chmod 0440 /etc/sudoers.d/"${user}" \
    && chown -R "${uid}":"${gid}" /home/"${user}"


## -----------------------------------------------------------------------------
## --- copy sourcecode ---------------------------------------------------------
## -----------------------------------------------------------------------------

COPY "Makefile" "/home/${user}/poc/"
COPY "stateless_ra_demo.c" "/home/${user}/poc/"
RUN chown -R "${user}:${user}" /home/"${user}/poc"


## -----------------------------------------------------------------------------
## --- configuration -----------------------------------------------------------
## -----------------------------------------------------------------------------

## set environment variables
USER "${uid}:${gid}"
ENV HOME=/home/"${user}"
WORKDIR /home/"${user}/poc"


## -----------------------------------------------------------------------------
## --- postamble ---------------------------------------------------------------
## -----------------------------------------------------------------------------

# ENTRYPOINT ["docker-entrypoint.sh"]
# CMD ["/bin/bash"]
