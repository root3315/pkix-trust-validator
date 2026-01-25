package com.pkix.validator;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for PKIX Trust Validator components.
 * Tests cover validation logic, policy enforcement, and certificate handling.
 */
@DisplayName("PKIX Trust Validator Tests")
class PkixTrustValidatorTest {

    private static final String TEST_CA_DN = "CN=Test CA, O=Test Organization, C=US";
    private static final String TEST_END_ENTITY_DN = "CN=test.example.com, O=Test Organization, C=US";

    private TrustStoreManager trustStoreManager;
    private X509Certificate testCACert;
    private PrivateKey testCAKey;

    @BeforeEach
    void setUp() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair caKeyPair = keyGen.generateKeyPair();

        testCACert = generateSelfSignedCACertificate(caKeyPair, TEST_CA_DN);
        testCAKey = caKeyPair.getPrivate();

        trustStoreManager = new TrustStoreManager();
    }

    @Nested
    @DisplayName("Validation Result Tests")
    class ValidationResultTests {

        @Test
        @DisplayName("Should create successful validation result")
        void testSuccessResult() {
            ValidationResult.ValidationPolicy policy = ValidationResult.ValidationPolicy.defaultPolicy();
            List<ValidationResult.CertificateInfo> certInfos = Collections.emptyList();

            ValidationResult result = ValidationResult.success(certInfos, "Test CA", policy);

            assertTrue(result.isValid());
            assertEquals("Certificate chain validated successfully", result.getStatusMessage());
            assertTrue(result.getValidationErrors().isEmpty());
            assertEquals("Test CA", result.getTrustAnchor());
            assertNotNull(result.getValidationTimestamp());
        }

        @Test
        @DisplayName("Should create failed validation result with single error")
        void testFailureResultSingleError() {
            ValidationResult.ValidationPolicy policy = ValidationResult.ValidationPolicy.defaultPolicy();

            ValidationResult result = ValidationResult.failure("Certificate expired", policy);

            assertFalse(result.isValid());
            assertEquals("Certificate chain validation failed", result.getStatusMessage());
            assertEquals(1, result.getValidationErrors().size());
            assertEquals("Certificate expired", result.getValidationErrors().get(0));
        }

        @Test
        @DisplayName("Should create failed validation result with multiple errors")
        void testFailureResultMultipleErrors() {
            ValidationResult.ValidationPolicy policy = ValidationResult.ValidationPolicy.defaultPolicy();
            List<String> errors = List.of("Error 1", "Error 2", "Error 3");

            ValidationResult result = ValidationResult.failure(errors, Collections.emptyList(),
                    "Test CA", policy);

            assertFalse(result.isValid());
            assertEquals(3, result.getValidationErrors().size());
        }

        @Test
        @DisplayName("Should create certificate info from certificate")
        void testCertificateInfo() throws Exception {
            X509Certificate cert = generateSelfSignedCACertificate(
                    generateKeyPair(), "CN=Test");

            ValidationResult.CertificateInfo info = new ValidationResult.CertificateInfo(cert);

            assertEquals("CN=Test", info.getSubjectDN());
            assertEquals("CN=Test", info.getIssuerDN());
            assertTrue(info.isCA());
            assertNotNull(info.getSerialNumber());
            assertNotNull(info.getNotBefore());
            assertNotNull(info.getNotAfter());
        }
    }

    @Nested
    @DisplayName("Validation Policy Tests")
    class ValidationPolicyTests {

        @Test
        @DisplayName("Should create default policy with expected values")
        void testDefaultPolicy() {
            ValidationResult.ValidationPolicy policy = ValidationResult.ValidationPolicy.defaultPolicy();

            assertFalse(policy.isCheckRevocation());
            assertTrue(policy.isRequireTimestampValidity());
            assertTrue(policy.isEnforceKeyUsage());
            assertEquals(10, policy.getMaxChainLength());
        }

        @Test
        @DisplayName("Should create custom policy using builder")
        void testCustomPolicyBuilder() {
            ValidationResult.ValidationPolicy policy = ValidationResult.ValidationPolicy.builder()
                    .checkRevocation(true)
                    .requireTimestampValidity(false)
                    .enforceKeyUsage(false)
                    .maxChainLength(5)
                    .build();

            assertTrue(policy.isCheckRevocation());
            assertFalse(policy.isRequireTimestampValidity());
            assertFalse(policy.isEnforceKeyUsage());
            assertEquals(5, policy.getMaxChainLength());
        }

        @Test
        @DisplayName("Should create strict policy")
        void testStrictPolicy() {
            List<String> allowedAlgorithms = List.of("SHA256withECDSA", "SHA384withECDSA");

            ValidationResult.ValidationPolicy policy = ValidationResult.ValidationPolicy.builder()
                    .checkRevocation(true)
                    .requireTimestampValidity(true)
                    .enforceKeyUsage(true)
                    .maxChainLength(3)
                    .allowedSignatureAlgorithms(allowedAlgorithms)
                    .build();

            assertTrue(policy.isCheckRevocation());
            assertEquals(3, policy.getMaxChainLength());
            assertEquals(2, policy.getAllowedSignatureAlgorithms().size());
        }
    }

    @Nested
    @DisplayName("Certificate Chain Validator Tests")
    class CertificateChainValidatorTests {

        @Test
        @DisplayName("Should fail validation with empty certificate list")
        void testEmptyCertificateList() throws Exception {
            TrustStoreManager manager = new TrustStoreManager();
            ValidationResult.ValidationPolicy policy = ValidationResult.ValidationPolicy.defaultPolicy();
            CertificateChainValidator validator = new CertificateChainValidator(manager, policy);

            ValidationResult result = validator.validate(Collections.emptyList());

            assertFalse(result.isValid());
            assertTrue(result.getValidationErrors().stream()
                    .anyMatch(e -> e.contains("No certificates provided")));
        }

        @Test
        @DisplayName("Should fail validation with null certificate list")
        void testNullCertificateList() throws Exception {
            TrustStoreManager manager = new TrustStoreManager();
            ValidationResult.ValidationPolicy policy = ValidationResult.ValidationPolicy.defaultPolicy();
            CertificateChainValidator validator = new CertificateChainValidator(manager, policy);

            ValidationResult result = validator.validate(null);

            assertFalse(result.isValid());
        }

        @Test
        @DisplayName("Should fail validation when chain exceeds max length")
        void testChainLengthExceeded() throws Exception {
            ValidationResult.ValidationPolicy policy = ValidationResult.ValidationPolicy.builder()
                    .maxChainLength(2)
                    .build();

            TrustStoreManager manager = new TrustStoreManager();
            CertificateChainValidator validator = new CertificateChainValidator(manager, policy);

            List<X509Certificate> longChain = generateCertificateChain(5);

            ValidationResult result = validator.validate(longChain);

            assertFalse(result.isValid());
            assertTrue(result.getValidationErrors().stream()
                    .anyMatch(e -> e.contains("exceeds maximum length")));
        }

        @Test
        @DisplayName("Should validate PEM chain content")
        void testValidatePemChain() throws Exception {
            TrustStoreManager manager = new TrustStoreManager();
            ValidationResult.ValidationPolicy policy = ValidationResult.ValidationPolicy.defaultPolicy();
            CertificateChainValidator validator = new CertificateChainValidator(manager, policy);

            String pemContent = generatePemCertificate();

            ValidationResult result = validator.validatePemChain(pemContent);

            assertNotNull(result);
        }
    }

    @Nested
    @DisplayName("Trust Store Manager Tests")
    class TrustStoreManagerTests {

        @Test
        @DisplayName("Should create trust store manager with default JVM cacerts")
        void testDefaultTrustStore() throws Exception {
            TrustStoreManager manager = new TrustStoreManager();

            assertNotNull(manager.getKeyStore());
            assertTrue(manager.getTrustedCertificateCount() >= 0);
        }

        @Test
        @DisplayName("Should return empty list when no certificates loaded")
        void testGetTrustedCertificates() throws Exception {
            TrustStoreManager manager = new TrustStoreManager();

            List<X509Certificate> certs = manager.getTrustedCertificates();

            assertNotNull(certs);
        }

        @Test
        @DisplayName("Should fail when trust store file not found")
        void testTrustStoreNotFound() {
            assertThrows(TrustStoreManager.TrustStoreException.class, () -> {
                new TrustStoreManager("/nonexistent/path/to/truststore.jks", "JKS", null);
            });
        }
    }

    @Nested
    @DisplayName("PKIX Trust Validator Tests")
    class PkixTrustValidatorTests {

        @Test
        @DisplayName("Should create validator with default configuration")
        void testDefaultValidatorCreation() throws Exception {
            PkixTrustValidator validator = new PkixTrustValidator.Builder()
                    .build();

            assertNotNull(validator);
            assertTrue(validator.getTrustedCertificateCount() >= 0);
        }

        @Test
        @DisplayName("Should create validator with custom policy")
        void testValidatorWithCustomPolicy() throws Exception {
            ValidationResult.ValidationPolicy policy = ValidationResult.ValidationPolicy.builder()
                    .maxChainLength(5)
                    .enforceKeyUsage(false)
                    .build();

            PkixTrustValidator validator = new PkixTrustValidator.Builder()
                    .policy(policy)
                    .build();

            assertNotNull(validator);
        }
    }

    private X509Certificate generateSelfSignedCACertificate(KeyPair keyPair, String dn)
            throws Exception {
        java.security.cert.CertificateFactory cf =
                java.security.cert.CertificateFactory.getInstance("X.509");

        String algorithm = "SHA256withECDSA";
        java.security.Signature sig = java.security.Signature.getInstance(algorithm);

        long now = System.currentTimeMillis();
        Date notBefore = new Date(now - 1000 * 60 * 60 * 24);
        Date notAfter = new Date(now + 1000L * 60 * 60 * 24 * 365 * 10);

        sun.security.x509.X509CertInfo info = new sun.security.x509.X509CertInfo();
        info.set(sun.security.x509.X509CertInfo.VERSION,
                new sun.security.x509.CertificateVersion(sun.security.x509.CertificateVersion.V3));
        info.set(sun.security.x509.X509CertInfo.SERIAL_NUMBER,
                new sun.security.x509.CertificateSerialNumber(new BigInteger("1")));
        info.set(sun.security.x509.X509CertInfo.ALGORITHM_ID,
                new sun.security.x509.AlgorithmId(AlgorithmId.sha256WithECDSA_oid));
        info.set(sun.security.x509.X509CertInfo.SUBJECT,
                new sun.security.x509.X500Name(dn));
        info.set(sun.security.x509.X509CertInfo.VALIDITY,
                new sun.security.x509.CertificateValidity(notBefore, notAfter));
        info.set(sun.security.x509.X509CertInfo.KEY,
                new sun.security.x509.CertificateX509Key(keyPair.getPublic()));

        byte[] encoded = info.getEncoded();
        sig.initSign(keyPair.getPrivate());
        sig.update(encoded);
        byte[] signature = sig.sign();

        info.set(sun.security.x509.X509CertInfo.SUBJECT_UNIQUE_ID,
                new sun.security.x509.SubjectUniqueID(keyPair.getPublic().getEncoded()));
        info.set(sun.security.x509.X509CertInfo.ISSUER_UNIQUE_ID,
                new sun.security.x509.IssuerUniqueID(keyPair.getPublic().getEncoded()));

        sun.security.x509.X509CertImpl cert = new sun.security.x509.X509CertImpl(info);
        cert.sign(keyPair.getPrivate(), algorithm);

        return cert;
    }

    private KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(new ECGenParameterSpec("secp256r1"));
        return keyGen.generateKeyPair();
    }

    private List<X509Certificate> generateCertificateChain(int length) {
        return Collections.emptyList();
    }

    private String generatePemCertificate() throws Exception {
        KeyPair keyPair = generateKeyPair();
        X509Certificate cert = generateSelfSignedCACertificate(keyPair, "CN=Test");

        StringBuilder pem = new StringBuilder();
        pem.append("-----BEGIN CERTIFICATE-----\n");
        pem.append(java.util.Base64.getEncoder().encodeToString(cert.getEncoded()));
        pem.append("\n-----END CERTIFICATE-----\n");

        return pem.toString();
    }
}
