FROM rust:1.87.0-alpine3.22 AS build

WORKDIR /app

RUN apk update && apk add musl-dev

COPY . .

RUN cargo build --release

FROM alpine:3.22

WORKDIR /app

COPY --from=build /app/target/release/trivy-operator-web-ui .

ENTRYPOINT [ "/app/trivy-operator-web-ui" ]