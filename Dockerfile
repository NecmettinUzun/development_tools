FROM maven:3.9-eclipse-temurin-22 AS build

WORKDIR /app
COPY pom.xml .
COPY src ./src

RUN mvn -q test package

FROM eclipse-temurin:22-jre

WORKDIR /app
COPY --from=build /app/target/classes ./classes

EXPOSE 8080

CMD ["java", "-cp", "classes", "tr.com.argela.nspm.Main", "8080"]