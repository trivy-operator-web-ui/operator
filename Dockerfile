FROM rust:1.93.1-alpine3.23 AS build

WORKDIR /app

RUN apk update \
    && apk add musl-dev

COPY . .

RUN cargo build --release

FROM alpine:3.23 AS production

ARG NOROOT_UID=3000
ARG USERNAME=trivy-operator-web-ui

WORKDIR /app

COPY --from=build /app/target/release/trivy-operator-web-ui .

# Fixed UID for Kubernetes Deployment ressource, no home dir, no password, default shell (nologin next ?)
RUN adduser ${USERNAME} -u ${NOROOT_UID} -H -D -s /bin/sh \
    && chown ${USERNAME} trivy-operator-web-ui \
    && chmod 500 trivy-operator-web-ui

USER ${USERNAME}

EXPOSE 8080

ENTRYPOINT [ "/app/trivy-operator-web-ui" ]