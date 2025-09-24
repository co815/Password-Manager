FROM maven:3.9.9-eclipse-temurin-21 AS build
WORKDIR /app

COPY pom.xml ./
COPY src ./src

ARG KEYSTORE_PASSWORD=changeit
RUN keytool -genkeypair \
        -alias PasswordManager \
        -keyalg RSA \
        -keysize 2048 \
        -storetype PKCS12 \
        -keystore src/main/resources/pass-man-keystore.p12 \
        -storepass "$KEYSTORE_PASSWORD" \
        -keypass "$KEYSTORE_PASSWORD" \
        -dname "CN=localhost" \
        -validity 3650

RUN mvn -B -DskipTests package

FROM eclipse-temurin:21-jre
WORKDIR /app

COPY --from=build /app/target/*.jar app.jar

EXPOSE 8080 8443

ENTRYPOINT ["java", "-jar", "app.jar"]