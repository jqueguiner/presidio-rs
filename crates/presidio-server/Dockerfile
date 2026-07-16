# Build the presidio-server binary and ship it on a slim runtime.
# Build context = repo root:  docker build -f crates/presidio-server/Dockerfile -t presidio-server .
FROM rust:1-slim AS build
WORKDIR /app
COPY . .
RUN cargo build --release -p presidio-server

FROM debian:bookworm-slim
RUN useradd -m app
COPY --from=build /app/target/release/presidio-server /usr/local/bin/presidio-server
USER app
ENV PORT=8080
EXPOSE 8080
CMD ["presidio-server"]
