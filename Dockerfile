# ============================================
# Offline Aadhaar KYC Validation - Dockerfile
# Multi-stage build for optimized image size
# ============================================

# -------------------- Stage 1: Build --------------------
FROM maven:3.9.6-eclipse-temurin-17-alpine AS builder

WORKDIR /app

# Copy pom.xml first for dependency caching
COPY pom.xml .

# Download dependencies (cached layer)
RUN mvn dependency:go-offline -B

# Copy source code
COPY src ./src

# Build application (skip tests for faster build)
RUN mvn clean package -DskipTests -B

# -------------------- Stage 2: Runtime --------------------
FROM eclipse-temurin:17-jre-alpine

# Labels
LABEL maintainer="Sberbank India - Enterprise Architecture"
LABEL version="2.0.0"
LABEL description="Offline Aadhaar KYC XML Validation Service"

# Create non-root user for security
RUN addgroup -g 1001 -S kycuser && \
    adduser -u 1001 -S kycuser -G kycuser

WORKDIR /app

# Create directories
RUN mkdir -p /app/logs /app/temp /app/certs && \
    chown -R kycuser:kycuser /app

# Copy JAR from builder stage
COPY --from=builder /app/target/offline-kyc-validation-*.jar app.jar

# Copy certificates directory (if exists)
# COPY --chown=kycuser:kycuser src/main/resources/certs /app/certs

# Set ownership
RUN chown kycuser:kycuser app.jar

# Switch to non-root user
USER kycuser

# Environment variables
ENV JAVA_OPTS="-Xms256m -Xmx512m -XX:+UseG1GC -XX:MaxGCPauseMillis=100"
ENV SERVER_PORT=8080
ENV SPRING_PROFILES_ACTIVE=prod
ENV KYC_VALIDATION_TEMP_DIR=/app/temp
ENV KYC_VALIDATION_SKIP_CERT_EXPIRY_CHECK=false

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/actuator/health || exit 1

# Entry point
ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar app.jar"]