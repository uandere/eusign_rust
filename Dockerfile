# Use the official Rust image
FROM --platform=linux/amd64 rust:latest

WORKDIR /EUSignCP-Linux-20250102

COPY . .

RUN apt-get update && apt-get -y install libclang-dev
ENV LD_LIBRARY_PATH="/EUSignCP-Linux-20250102/Modules:${LD_LIBRARY_PATH}"
RUN cargo build --release


# Run the compiled binary
CMD ["./target/release/EUSignCP-Linux-20250102"]