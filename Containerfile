# SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
# SPDX-License-Identifier: CC0-1.0

# Stage 1: Build stage
FROM docker.io/library/eclipse-temurin:25-jdk-alpine@sha256:7ace075f29555df6696750ee3caffea4fb542a1db8a5b1e7578129162f071c03 AS builder

LABEL maintainer="Digg - Agency for Digital Government"
LABEL description="Build stage for Wallet PKI Tool"

# Install dependencies needed for building
# hadolint ignore=DL3018
RUN apk add --no-cache curl

# Create app directory
WORKDIR /app

# Copy Maven wrapper and pom.xml
COPY .mvn/ .mvn/
COPY mvnw pom.xml ./

# Make mvnw executable and download dependencies (cached if pom.xml doesn't change)
RUN chmod +x ./mvnw && \
    ./mvnw dependency:go-offline -B

# Copy source code
COPY src ./src

# Build the application (skip checkstyle and formatter in Docker build)
RUN ./mvnw clean package -DskipTests -Dcheckstyle.skip=true -Dformatter.skip=true -B

# Stage 2: Runtime stage
FROM cgr.dev/chainguard/jre:latest@sha256:62ad89cd0af8e0c8750672586615e2c7ee990e5c83527dca99ae83891ad0bd2f AS runtime

LABEL maintainer="Digg - Agency for Digital Government"
LABEL description="Wallet PKI Tool"

WORKDIR /app

# Copy built jar from builder stage (nonroot user: 65532)
COPY --from=builder --chown=65532:65532 /app/target/wallet-pki-tool.jar ./wallet-pki-tool.jar

# JVM options are set directly in ENTRYPOINT since distroless has no shell
ENTRYPOINT ["java", "-XX:+UseContainerSupport", "-XX:MaxRAMPercentage=75.0", "-XX:+UseG1GC", "-XX:+UseStringDeduplication", "-Djava.security.egd=file:/dev/./urandom", "-Dfile.encoding=UTF-8", "-jar", "wallet-pki-tool.jar"]
