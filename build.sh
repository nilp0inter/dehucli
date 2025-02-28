#!/bin/bash

# Build the project
echo "Compiling and building uberjar..."
mkdir -p target

# Make sure we have AOT compilation
clj -e "(compile 'dehucli.core)"
clj -e "(compile 'dehucli.api)"
clj -e "(compile 'dehucli.security)"
clj -e "(compile 'dehucli.auth)"
clj -e "(compile 'dehucli.PasswordCallback)"

# Create the uberjar
clj -X:uberjar

# Check if uberjar was created
if [ -f "dehucli.jar" ]; then
    echo "Uberjar created successfully: dehucli.jar"
    chmod +x dehucli.jar
    echo "To run: java -jar dehucli.jar [options] command [args]"
else
    echo "Failed to create uberjar"
    exit 1
fi