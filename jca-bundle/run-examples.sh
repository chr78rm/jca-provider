#!/bin/bash
export JAVA_HOME=/opt/java/jdk1.8.0_51
${JAVA_HOME}/bin/java -ea:de.christofreichardt.crypto.examples... -Djava.util.logging.config.file=./logging.properties -cp ./target/jca-bundle-0.0.3-SNAPSHOT.jar de.christofreichardt.crypto.examples.Main

