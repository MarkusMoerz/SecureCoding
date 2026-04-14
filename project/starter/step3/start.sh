#!/bin/bash

# Function to handle termination signals
term_handler() {
  echo "Received termination signal. Exiting..."
  exit 0
}

# Trap termination signals
trap 'term_handler' INT TERM

gcc /app/generate_hashed_users.c /app/hash_utils.c -o /app/generate -lssl -lcrypto

/app/generate

while true; do
  /app/login
done