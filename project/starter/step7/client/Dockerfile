FROM gcc:latest
RUN apt-get update && apt-get install -y libssl-dev 

COPY . /app/
WORKDIR /app
RUN gcc verify_update.c -o verify_update -lssl -lcrypto
