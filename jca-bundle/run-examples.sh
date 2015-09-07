#!/bin/bash
export JAVA_HOME=/opt/java/jdk1.8.0_51
${JAVA_HOME}/bin/java -ea:de.christofreichardt.crypto.examples... -Djava.util.logging.config.file=./logging.properties \
-cp ./target/jca-bundle-0.1.0-beta.jar de.christofreichardt.crypto.examples.Main $1

