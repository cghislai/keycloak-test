FROM openjdk:11-jre

ADD target/backend-thorntail.jar /opt/thorntail.jar

EXPOSE 8443 8787
ENTRYPOINT ["java", "-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=0.0.0.0:8787", "-jar", "/opt/thorntail.jar" ]
