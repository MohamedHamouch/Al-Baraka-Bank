# syntax=docker/dockerfile:1

FROM eclipse-temurin:17-jre
WORKDIR /opt/app
COPY target/*.jar app.jar
ENV JAVA_OPTS=""
EXPOSE 8080
ENTRYPOINT ["sh","-c","java $JAVA_OPTS -jar app.jar"]
