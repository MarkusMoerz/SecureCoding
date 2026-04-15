# Use the official GCC image from the Docker Hub
FROM gcc:latest

# Install build essentials, and legacy services
RUN apt-get update && \
    apt-get install -y build-essential net-tools nmap libssl-dev && \
    apt-get clean


# Set the working directory inside the container
WORKDIR /app

# Copy the C program to the working directory
COPY login.c /app/
COPY users.txt /app/
COPY start.sh /app/

# Compile programs
RUN gcc /app/login.c -o /app/login -lssl -lcrypto

# Make start.sh executable
RUN chmod +x /app/start.sh

# Specify the command to run the program
CMD ["/bin/bash", "/app/start.sh"]