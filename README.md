# PKIX Trust Validator

Enterprise-grade X.509 certificate chain validation for Java applications.

## Overview

PKIX Trust Validator is a comprehensive Java library for validating X.509 certificate chains against configurable trust stores. It implements RFC 5280 PKIX validation rules and provides both programmatic API and command-line interface for certificate validation operations.

## Features

- **Complete PKIX Validation**: Full implementation of RFC 5280 certificate path validation
- **Configurable Trust Stores**: Support for JKS, PKCS12, and PEM format trust anchors
- **Policy-Based Validation**: Flexible validation policies (default, strict, permissive)
- **Signature Algorithm Enforcement**: Configurable allowed signature algorithms
- **Key Usage Validation**: Enforce proper key usage and extended key usage constraints
- **Chain Length Limits**: Configurable maximum certificate chain depth
- **Detailed Reporting**: Comprehensive validation results with certificate metadata
- **Bouncy Castle Integration**: Enhanced cryptographic algorithm support

## Requirements

- Java 11 or higher
- Maven 3.6 or higher

## Installation

### Build from Source

```bash
git clone https://github.com/your-org/pkix-trust-validator.git
cd pkix-trust-validator
mvn clean package
```

### Maven Dependency

Add the following dependency to your `pom.xml`:

```xml
<dependency>
    <groupId>com.pkix</groupId>
    <artifactId>pkix-trust-validator</artifactId>
    <version>1.0.0</version>
</dependency>
```

### Gradle Dependency

```groovy
implementation 'com.pkix:pkix-trust-validator:1.0.0'
```

## Usage

### Command-Line Interface

#### Validate a Certificate

```bash
java -jar pkix-trust-validator.jar validate server.pem
```

#### Validate with Custom Trust Store

```bash
java -jar pkix-trust-validator.jar validate \
    --truststore /path/to/cacerts.jks \
    --truststore-type JKS \
    --password changeit \
    server.pem
```

#### Use Strict Validation Policy

```bash
java -jar pkix-trust-validator.jar validate \
    --policy strict \
    certificate-chain.pem
```

#### Display Certificate Information

```bash
java -jar pkix-trust-validator.jar info certificate.pem
```

#### View Help

```bash
java -jar pkix-trust-validator.jar help
```

### Programmatic API

#### Basic Validation

```java
import com.pkix.validator.*;

// Create validator with default configuration
PkixTrustValidator validator = new PkixTrustValidator.Builder().build();

// Validate a certificate file
ValidationResult result = validator.validateCertificate("/path/to/cert.pem");

if (result.isValid()) {
    System.out.println("Certificate is valid!");
} else {
    for (String error : result.getValidationErrors()) {
        System.err.println("Validation error: " + error);
    }
}
```

#### Custom Validation Policy

```java
import com.pkix.validator.*;

// Create a strict validation policy
ValidationResult.ValidationPolicy policy = ValidationResult.ValidationPolicy.builder()
    .checkRevocation(true)
    .requireTimestampValidity(true)
    .enforceKeyUsage(true)
    .maxChainLength(5)
    .allowedSignatureAlgorithms(List.of(
        "SHA256withRSA",
        "SHA256withECDSA",
        "SHA384withECDSA"
    ))
    .build();

// Create validator with custom policy
PkixTrustValidator validator = new PkixTrustValidator.Builder()
    .policy(policy)
    .build();

// Validate certificate chain
ValidationResult result = validator.validateCertificate("chain.pem");
```

#### Load Custom Trust Store

```java
import com.pkix.validator.*;

// Load trust store from JKS file
TrustStoreManager trustStore = new TrustStoreManager(
    "/path/to/truststore.jks",
    "JKS",
    "changeit".toCharArray()
);

// Load trust store from PEM file
TrustStoreManager trustStore = TrustStoreManager.fromPemFile(
    "/path/to/ca-certificates.pem"
);

// Create validator with custom trust store
CertificateChainValidator chainValidator = new CertificateChainValidator(
    trustStore,
    ValidationResult.ValidationPolicy.defaultPolicy()
);
```

#### Validate PEM Content Directly

```java
import com.pkix.validator.*;

String pemContent = """
    -----BEGIN CERTIFICATE-----
    MIIDXTCCAkWgAwIBAgIJAJC1HiIAZAiUMA0Gc...
    -----END CERTIFICATE-----
    """;

PkixTrustValidator validator = new PkixTrustValidator.Builder().build();
ValidationResult result = validator.validatePemChain(pemContent);
```

#### Get Certificate Information

```java
import com.pkix.validator.*;

PkixTrustValidator validator = new PkixTrustValidator.Builder().build();
List<ValidationResult.CertificateInfo> certInfos = 
    validator.getCertificateInfo("/path/to/cert.pem");

for (ValidationResult.CertificateInfo info : certInfos) {
    System.out.println("Subject: " + info.getSubjectDN());
    System.out.println("Issuer: " + info.getIssuerDN());
    System.out.println("Valid: " + info.getNotBefore() + " to " + info.getNotAfter());
    System.out.println("Key Usage: " + info.getKeyUsage());
}
```

## How It Works

### Validation Process

1. **Certificate Parsing**: Load and parse certificates from PEM or DER format
2. **Chain Structure Validation**: Verify issuer-subject relationships between certificates
3. **Validity Period Check**: Ensure all certificates are within their validity period
4. **Signature Verification**: Validate cryptographic signatures using PKIX algorithm
5. **Trust Anchor Verification**: Confirm chain terminates at a trusted root
6. **Key Usage Enforcement**: Validate key usage and extended key usage constraints
7. **Algorithm Policy Check**: Verify signature algorithms meet policy requirements

### Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   PkixTrustValidator                     │
│              (Main Entry Point / CLI)                    │
└─────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────┐
│              CertificateChainValidator                   │
│           (Core PKIX Validation Engine)                  │
└─────────────────────────────────────────────────────────┘
                            │
            ┌───────────────┼───────────────┐
            ▼               ▼               ▼
┌──────────────────┐ ┌──────────────────┐ ┌──────────────────┐
│  TrustStore      │ │ ValidationResult │ │ ValidationPolicy │
│  Manager         │ │                  │ │                  │
└──────────────────┘ └──────────────────┘ └──────────────────┘
```

### Components

- **PkixTrustValidator**: Main entry point providing CLI and high-level API
- **CertificateChainValidator**: Core validation engine implementing PKIX rules
- **TrustStoreManager**: Manages trust anchors from various sources
- **ValidationResult**: Immutable container for validation results
- **ValidationPolicy**: Configurable validation rules and constraints

## Validation Policies

| Policy | Description |
|--------|-------------|
| `default` | Standard validation with timestamp and key usage checks |
| `strict` | Enhanced security with shorter chain limits and algorithm restrictions |
| `permissive` | Relaxed validation for testing and development |

## Supported Signature Algorithms

- SHA256withRSA
- SHA384withRSA
- SHA512withRSA
- SHA256withECDSA
- SHA384withECDSA
- SHA512withECDSA
- SHA256withRSAandMGF1
- SHA384withRSAandMGF1
- SHA512withRSAandMGF1

## Running Tests

```bash
mvn test
```

## Building Executable JAR

```bash
mvn clean package
```

The shaded JAR with all dependencies will be created at `target/pkix-trust-validator-1.0.0.jar`.

## License

Apache License 2.0

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests: `mvn test`
5. Submit a pull request

## Project Structure

```
pkix-trust-validator/
├── pom.xml
├── README.md
├── src/
│   ├── main/
│   │   └── java/
│   │       └── com/
│   │           └── pkix/
│   │               └── validator/
│   │                   ├── PkixTrustValidator.java
│   │                   ├── CertificateChainValidator.java
│   │                   ├── TrustStoreManager.java
│   │                   └── ValidationResult.java
│   └── test/
│       └── java/
│           └── com/
│               └── pkix/
│                   └── validator/
│                       └── PkixTrustValidatorTest.java
└── target/
```
