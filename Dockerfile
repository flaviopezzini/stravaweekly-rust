FROM rust:1.84-alpine3.21 AS builder
RUN apk add --no-cache musl-dev

WORKDIR /usr/src/rust-strava-weekly

COPY . .

RUN cargo build --release

FROM alpine:3.21.2

# Copy the binary
COPY --from=builder /usr/src/rust-strava-weekly/target/release/rust-strava-weekly /
# Copy the static files
COPY --from=builder /usr/src/rust-strava-weekly/static/ /static/

ENV PORT 3000
EXPOSE 3000

CMD ["./rust-strava-weekly"]
