package com.pkix.validator;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.logging.ConsoleHandler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Enterprise-grade X.509 certificate chain validation tool.
 * 
 * This main entry point provides command-line interface for validating
 * certificate chains against trust stores, with support for various
 * input formats and configurable validation policies.
 * 
 * Usage examples:
 *   java -jar pkix-trust-validator.jar validate /path/to/cert.pem
 *   java -jar pkix-trust-validator.jar validate --truststore /path/to/trust.jks /path/to/cert.pem
 *   java -jar pkix-trust-validator.jar validate --policy strict /path/to/chain.pem
 *   java -jar pkix-trust-validator.jar info /path/to/cert.pem
 */
public class PkixTrustValidator {

    private static final Logger logger = Logger.getLogger(PkixTrustValidator.class.getName());

    private static final String VERSION = "1.0.0";

    private static final List<String> DEFAULT_ALLOWED_SIGNATURE_ALGORITHMS = Arrays.asList(
            "SHA256withRSA", "SHA384withRSA", "SHA512withRSA",
            "SHA256withECDSA", "SHA384withECDSA", "SHA512withECDSA",
            "SHA256withRSAandMGF1", "SHA384withRSAandMGF1", "SHA512withRSAandMGF1"
    );

    static {
        Security.addProvider(new BouncyCastleProvider());
        configureLogging();
    }

    private final TrustStoreManager trustStoreManager;
    private final CertificateChainValidator validator;
    private final ValidationResult.ValidationPolicy policy;

    private PkixTrustValidator(Builder builder) throws TrustStoreManager.TrustStoreException {
        this.trustStoreManager = new TrustStoreManager(
                builder.trustStorePath,
                builder.trustStoreType,
                builder.trustStorePassword != null ? 
                        builder.trustStorePassword.toCharArray() : null
        );
        this.policy = builder.policy;
        this.validator = new CertificateChainValidator(trustStoreManager, policy);
    }

    private static void configureLogging() {
        Logger rootLogger = Logger.getLogger("");
        rootLogger.setLevel(Level.INFO);
        
        ConsoleHandler handler = new ConsoleHandler();
        handler.setLevel(Level.INFO);
        handler.setFormatter(new SimpleFormatter());
        
        rootLogger.addHandler(handler);
    }

    /**
     * Validates a certificate file against the configured trust store.
     *
     * @param certPath path to the certificate file
     * @return validation result
     */
    public ValidationResult validateCertificate(String certPath) {
        logger.info("Validating certificate: " + certPath);
        return validator.validateCertificateFile(certPath);
    }

    /**
     * Validates a certificate chain from PEM content.
     *
     * @param pemContent PEM-encoded certificate chain
     * @return validation result
     */
    public ValidationResult validatePemChain(String pemContent) {
        return validator.validatePemChain(pemContent);
    }

    /**
     * Returns information about a certificate without validation.
     *
     * @param certPath path to the certificate file
     * @return certificate information
     * @throws IOException if the certificate cannot be read
     */
    public List<ValidationResult.CertificateInfo> getCertificateInfo(String certPath)
            throws IOException {
        String content = Files.readString(Path.of(certPath));
        List<ValidationResult.CertificateInfo> infoList = new ArrayList<>();

        String[] certBlocks = content.split("-----END CERTIFICATE-----");
        for (String certBlock : certBlocks) {
            String trimmed = certBlock.trim();
            if (trimmed.isEmpty() || !trimmed.contains("-----BEGIN CERTIFICATE-----")) {
                continue;
            }

            try {
                java.security.cert.CertificateFactory cf =
                        java.security.cert.CertificateFactory.getInstance("X.509");
                String base64Cert = trimmed
                        .replace("-----BEGIN CERTIFICATE-----", "")
                        .replaceAll("\\s+", "");

                if (!base64Cert.isEmpty()) {
                    byte[] certBytes = java.util.Base64.getDecoder().decode(base64Cert);
                    java.security.cert.X509Certificate cert =
                            (java.security.cert.X509Certificate) cf.generateCertificate(
                                    new java.io.ByteArrayInputStream(certBytes));
                    infoList.add(new ValidationResult.CertificateInfo(cert));
                }
            } catch (Exception e) {
                logger.warning("Failed to parse certificate: " + e.getMessage());
            }
        }

        return infoList;
    }

    /**
     * Returns the number of trusted certificates in the trust store.
     *
     * @return count of trusted certificates
     */
    public int getTrustedCertificateCount() {
        return trustStoreManager.getTrustedCertificateCount();
    }

    /**
     * Prints validation result to console.
     *
     * @param result the validation result to display
     */
    public static void printResult(ValidationResult result) {
        System.out.println();
        System.out.println("=".repeat(60));
        System.out.println("CERTIFICATE VALIDATION RESULT");
        System.out.println("=".repeat(60));
        System.out.println("Status: " + (result.isValid() ? "VALID" : "INVALID"));
        System.out.println("Message: " + result.getStatusMessage());
        System.out.println("Timestamp: " + result.getValidationTimestamp());
        System.out.println();

        if (!result.getValidationErrors().isEmpty()) {
            System.out.println("ERRORS:");
            for (String error : result.getValidationErrors()) {
                System.out.println("  - " + error);
            }
            System.out.println();
        }

        if (!result.getCertificateChain().isEmpty()) {
            System.out.println("CERTIFICATE CHAIN:");
            int index = 1;
            for (ValidationResult.CertificateInfo cert : result.getCertificateChain()) {
                System.out.println();
                System.out.println("  [" + index + "] " + cert.getSubjectDN());
                System.out.println("      Issuer: " + cert.getIssuerDN());
                System.out.println("      Serial: " + cert.getSerialNumber());
                System.out.println("      Valid: " + cert.getNotBefore() + " to " + cert.getNotAfter());
                System.out.println("      Algorithm: " + cert.getSignatureAlgorithm());
                System.out.println("      Is CA: " + cert.isCA());
                if (!cert.getKeyUsage().isEmpty()) {
                    System.out.println("      Key Usage: " + String.join(", ", cert.getKeyUsage()));
                }
                index++;
            }
            System.out.println();
        }

        System.out.println("POLICY:");
        System.out.println("  Check Revocation: " + result.getAppliedPolicy().isCheckRevocation());
        System.out.println("  Enforce Key Usage: " + result.getAppliedPolicy().isEnforceKeyUsage());
        System.out.println("  Max Chain Length: " + result.getAppliedPolicy().getMaxChainLength());
        System.out.println("=".repeat(60));
    }

    /**
     * Prints certificate information to console.
     *
     * @param certInfos list of certificate information
     */
    public static void printCertificateInfo(List<ValidationResult.CertificateInfo> certInfos) {
        System.out.println();
        System.out.println("=".repeat(60));
        System.out.println("CERTIFICATE INFORMATION");
        System.out.println("=".repeat(60));

        int index = 1;
        for (ValidationResult.CertificateInfo cert : certInfos) {
            System.out.println();
            System.out.println("Certificate " + index + ":");
            System.out.println("  Subject: " + cert.getSubjectDN());
            System.out.println("  Issuer: " + cert.getIssuerDN());
            System.out.println("  Serial Number: " + cert.getSerialNumber());
            System.out.println("  Version: " + cert.getVersion());
            System.out.println("  Signature Algorithm: " + cert.getSignatureAlgorithm());
            System.out.println("  Valid From: " + cert.getNotBefore());
            System.out.println("  Valid To: " + cert.getNotAfter());
            System.out.println("  Is CA: " + cert.isCA());

            if (!cert.getKeyUsage().isEmpty()) {
                System.out.println("  Key Usage:");
                for (String usage : cert.getKeyUsage()) {
                    System.out.println("    - " + usage);
                }
            }

            if (!cert.getExtendedKeyUsage().isEmpty()) {
                System.out.println("  Extended Key Usage:");
                for (String usage : cert.getExtendedKeyUsage()) {
                    System.out.println("    - " + usage);
                }
            }

            index++;
        }

        System.out.println();
        System.out.println("=".repeat(60));
    }

    public static void main(String[] args) {
        if (args.length == 0) {
            printUsage();
            System.exit(1);
        }

        String command = args[0];

        switch (command.toLowerCase()) {
            case "validate":
                handleValidate(Arrays.copyOfRange(args, 1, args.length));
                break;
            case "info":
                handleInfo(Arrays.copyOfRange(args, 1, args.length));
                break;
            case "version":
                System.out.println("PKIX Trust Validator version " + VERSION);
                break;
            case "help":
            case "--help":
            case "-h":
                printUsage();
                break;
            default:
                System.err.println("Unknown command: " + command);
                printUsage();
                System.exit(1);
        }
    }

    private static void handleValidate(String[] args) {
        String trustStorePath = null;
        String trustStoreType = null;
        String trustStorePassword = null;
        String policyType = "default";
        String certPath = null;

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--truststore":
                    if (i + 1 < args.length) {
                        trustStorePath = args[++i];
                    }
                    break;
                case "--truststore-type":
                    if (i + 1 < args.length) {
                        trustStoreType = args[++i];
                    }
                    break;
                case "--password":
                    if (i + 1 < args.length) {
                        trustStorePassword = args[++i];
                    }
                    break;
                case "--policy":
                    if (i + 1 < args.length) {
                        policyType = args[++i];
                    }
                    break;
                default:
                    if (!args[i].startsWith("-")) {
                        certPath = args[i];
                    }
                    break;
            }
        }

        if (certPath == null) {
            System.err.println("Error: Certificate path is required");
            printUsage();
            System.exit(1);
        }

        File certFile = new File(certPath);
        if (!certFile.exists()) {
            System.err.println("Error: Certificate file not found: " + certPath);
            System.exit(1);
        }

        try {
            ValidationResult.ValidationPolicy policy = buildPolicy(policyType);
            PkixTrustValidator validator = new Builder()
                    .trustStore(trustStorePath, trustStoreType, trustStorePassword)
                    .policy(policy)
                    .build();

            ValidationResult result = validator.validateCertificate(certPath);
            printResult(result);

            System.exit(result.isValid() ? 0 : 1);

        } catch (TrustStoreManager.TrustStoreException e) {
            System.err.println("Error loading trust store: " + e.getMessage());
            System.exit(1);
        }
    }

    private static void handleInfo(String[] args) {
        if (args.length == 0) {
            System.err.println("Error: Certificate path is required");
            printUsage();
            System.exit(1);
        }

        String certPath = args[0];
        File certFile = new File(certPath);
        if (!certFile.exists()) {
            System.err.println("Error: Certificate file not found: " + certPath);
            System.exit(1);
        }

        try {
            PkixTrustValidator validator = new Builder().build();
            List<ValidationResult.CertificateInfo> certInfos = validator.getCertificateInfo(certPath);

            if (certInfos.isEmpty()) {
                System.err.println("No certificates found in file: " + certPath);
                System.exit(1);
            }

            printCertificateInfo(certInfos);

        } catch (IOException e) {
            System.err.println("Error reading certificate: " + e.getMessage());
            System.exit(1);
        }
    }

    private static ValidationResult.ValidationPolicy buildPolicy(String policyType) {
        switch (policyType.toLowerCase()) {
            case "strict":
                return ValidationResult.ValidationPolicy.builder()
                        .checkRevocation(false)
                        .requireTimestampValidity(true)
                        .enforceKeyUsage(true)
                        .maxChainLength(5)
                        .allowedSignatureAlgorithms(DEFAULT_ALLOWED_SIGNATURE_ALGORITHMS)
                        .build();
            case "permissive":
                return ValidationResult.ValidationPolicy.builder()
                        .checkRevocation(false)
                        .requireTimestampValidity(false)
                        .enforceKeyUsage(false)
                        .maxChainLength(20)
                        .build();
            case "default":
            default:
                return ValidationResult.ValidationPolicy.builder()
                        .checkRevocation(false)
                        .requireTimestampValidity(true)
                        .enforceKeyUsage(true)
                        .maxChainLength(10)
                        .allowedSignatureAlgorithms(DEFAULT_ALLOWED_SIGNATURE_ALGORITHMS)
                        .build();
        }
    }

    private static void printUsage() {
        System.out.println();
        System.out.println("PKIX Trust Validator v" + VERSION);
        System.out.println("Enterprise-grade X.509 certificate chain validation");
        System.out.println();
        System.out.println("Usage:");
        System.out.println("  pkix-trust-validator <command> [options] [arguments]");
        System.out.println();
        System.out.println("Commands:");
        System.out.println("  validate <cert.pem>    Validate a certificate or chain");
        System.out.println("  info <cert.pem>        Display certificate information");
        System.out.println("  version                Show version information");
        System.out.println("  help                   Show this help message");
        System.out.println();
        System.out.println("Validate Options:");
        System.out.println("  --truststore <path>    Path to trust store file");
        System.out.println("  --truststore-type <type>  Trust store type (JKS, PKCS12)");
        System.out.println("  --password <password>  Trust store password");
        System.out.println("  --policy <policy>      Validation policy (default, strict, permissive)");
        System.out.println();
        System.out.println("Examples:");
        System.out.println("  java -jar pkix-trust-validator.jar validate server.pem");
        System.out.println("  java -jar pkix-trust-validator.jar validate --policy strict chain.pem");
        System.out.println("  java -jar pkix-trust-validator.jar validate --truststore cacerts.jks cert.pem");
        System.out.println("  java -jar pkix-trust-validator.jar info certificate.pem");
        System.out.println();
    }

    /**
     * Builder for creating PkixTrustValidator instances.
     */
    public static class Builder {
        private String trustStorePath;
        private String trustStoreType;
        private String trustStorePassword;
        private ValidationResult.ValidationPolicy policy = ValidationResult.ValidationPolicy.defaultPolicy();

        public Builder trustStore(String path, String type, String password) {
            this.trustStorePath = path;
            this.trustStoreType = type;
            this.trustStorePassword = password;
            return this;
        }

        public Builder policy(ValidationResult.ValidationPolicy policy) {
            this.policy = policy;
            return this;
        }

        public PkixTrustValidator build() throws TrustStoreManager.TrustStoreException {
            return new PkixTrustValidator(this);
        }
    }
}
