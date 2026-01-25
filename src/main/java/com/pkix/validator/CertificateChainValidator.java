package com.pkix.validator;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertPathValidatorResult;
import java.security.cert.CertPathValidatorException.BasicReason;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;

/**
 * Core certificate chain validation engine implementing PKIX validation rules.
 * Performs comprehensive validation including signature verification, validity
 * period checks, key usage enforcement, and trust anchor verification.
 */
public class CertificateChainValidator {

    private static final Logger logger = Logger.getLogger(CertificateChainValidator.class.getName());

    private static final Set<String> WEAK_SIGNATURE_ALGORITHMS = new HashSet<>(Arrays.asList(
            "MD2withRSA", "MD5withRSA", "SHA1withRSA", "SHA1withDSA", "MD5withRSAandMGF1"
    ));

    private static final String OID_SERVER_AUTH = "1.3.6.1.5.5.7.3.1";
    private static final String OID_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2";
    private static final String OID_CODE_SIGNING = "1.3.6.1.5.5.7.3.3";
    private static final String OID_EMAIL_PROTECTION = "1.3.6.1.5.5.7.3.4";

    private final TrustStoreManager trustStoreManager;
    private final ValidationResult.ValidationPolicy policy;

    /**
     * Creates a new CertificateChainValidator.
     *
     * @param trustStoreManager the trust store manager containing trusted anchors
     * @param policy the validation policy to apply
     */
    public CertificateChainValidator(TrustStoreManager trustStoreManager,
                                     ValidationResult.ValidationPolicy policy) {
        this.trustStoreManager = trustStoreManager;
        this.policy = policy;
    }

    /**
     * Validates a certificate chain against the configured trust store.
     *
     * @param certificates the certificate chain to validate (leaf first)
     * @return the validation result containing status and certificate information
     */
    public ValidationResult validate(List<X509Certificate> certificates) {
        List<String> errors = new ArrayList<>();
        List<ValidationResult.CertificateInfo> certInfos = new ArrayList<>();

        if (certificates == null || certificates.isEmpty()) {
            return ValidationResult.failure("No certificates provided for validation", policy);
        }

        if (certificates.size() > policy.getMaxChainLength()) {
            errors.add("Certificate chain exceeds maximum length of " + policy.getMaxChainLength());
            return ValidationResult.failure(errors, extractCertInfo(certificates),
                    getTrustAnchorSubject(), policy);
        }

        for (X509Certificate cert : certificates) {
            certInfos.add(new ValidationResult.CertificateInfo(cert));
        }

        if (policy.isRequireTimestampValidity()) {
            errors.addAll(validateValidityPeriods(certificates));
        }

        if (policy.isEnforceKeyUsage()) {
            errors.addAll(validateKeyUsage(certificates));
        }

        errors.addAll(validateSignatureAlgorithms(certificates));
        errors.addAll(validateChainStructure(certificates));

        if (!errors.isEmpty()) {
            return ValidationResult.failure(errors, certInfos, getTrustAnchorSubject(), policy);
        }

        try {
            CertPathValidatorResult result = performPKIXValidation(certificates);
            if (result != null) {
                return ValidationResult.success(certInfos, getTrustAnchorSubject(), policy);
            }
        } catch (CertPathValidatorException e) {
            String errorMsg = buildDetailedErrorMessage(e, certificates);
            errors.add(errorMsg);
            logger.log(Level.FINE, "PKIX validation failed", e);
        } catch (Exception e) {
            errors.add("Validation error: " + e.getMessage());
            logger.log(Level.FINE, "Unexpected validation error", e);
        }

        return ValidationResult.failure(errors, certInfos, getTrustAnchorSubject(), policy);
    }

    /**
     * Validates a single certificate file.
     *
     * @param certPath path to the certificate file (PEM or DER format)
     * @return the validation result
     */
    public ValidationResult validateCertificateFile(String certPath) {
        try {
            X509Certificate cert = loadCertificate(certPath);
            return validate(Collections.singletonList(cert));
        } catch (CertificateException | java.io.IOException e) {
            return ValidationResult.failure("Failed to load certificate: " + e.getMessage(), policy);
        }
    }

    /**
     * Validates a certificate chain from PEM-encoded content.
     *
     * @param pemContent PEM-encoded certificate chain
     * @return the validation result
     */
    public ValidationResult validatePemChain(String pemContent) {
        try {
            List<X509Certificate> certs = parsePemCertificates(pemContent);
            if (certs.isEmpty()) {
                return ValidationResult.failure("No certificates found in PEM content", policy);
            }
            return validate(certs);
        } catch (CertificateException | java.io.IOException e) {
            return ValidationResult.failure("Failed to parse PEM content: " + e.getMessage(), policy);
        }
    }

    private CertPathValidatorResult performPKIXValidation(List<X509Certificate> certificates)
            throws CertPathValidatorException, NoSuchAlgorithmException, InvalidKeyException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        CertPath certPath = cf.generateCertPath(certificates);

        Set<TrustAnchor> trustAnchors = buildTrustAnchors();
        if (trustAnchors.isEmpty()) {
            throw new CertPathValidatorException("No trust anchors available");
        }

        PKIXParameters params = new PKIXParameters(trustAnchors);
        params.setRevocationEnabled(policy.isCheckRevocation());
        params.setDate(new Date());

        CertPathValidator validator = CertPathValidator.getInstance("PKIX");
        return validator.validate(certPath, params);
    }

    private Set<TrustAnchor> buildTrustAnchors() {
        Set<TrustAnchor> anchors = new HashSet<>();
        for (X509Certificate cert : trustStoreManager.getTrustedCertificates()) {
            anchors.add(new TrustAnchor(cert, null));
        }
        return anchors;
    }

    private List<String> validateValidityPeriods(List<X509Certificate> certificates) {
        List<String> errors = new ArrayList<>();
        Instant now = Instant.now();

        for (int i = 0; i < certificates.size(); i++) {
            X509Certificate cert = certificates.get(i);
            String certSubject = cert.getSubjectX500Principal().getName();

            try {
                cert.checkValidity();
            } catch (CertificateException e) {
                if (now.isBefore(cert.getNotBefore().toInstant())) {
                    errors.add(String.format("Certificate %d (%s) is not yet valid (not before: %s)",
                            i + 1, truncate(certSubject, 60), cert.getNotBefore()));
                } else if (now.isAfter(cert.getNotAfter().toInstant())) {
                    errors.add(String.format("Certificate %d (%s) has expired (not after: %s)",
                            i + 1, truncate(certSubject, 60), cert.getNotAfter()));
                }
            }
        }

        return errors;
    }

    private List<String> validateKeyUsage(List<X509Certificate> certificates) {
        List<String> errors = new ArrayList<>();

        for (int i = 0; i < certificates.size(); i++) {
            X509Certificate cert = certificates.get(i);
            boolean isEndEntity = (i == 0);
            boolean isCA = cert.getBasicConstraints() >= 0;

            if (isCA) {
                boolean[] keyUsage = cert.getKeyUsage();
                if (keyUsage != null && keyUsage.length > 5) {
                    if (!keyUsage[5]) {
                        errors.add(String.format("CA certificate at position %d lacks keyCertSign key usage", i + 1));
                    }
                }
            }

            if (isEndEntity && !policy.getRequiredExtendedKeyUsage().isEmpty()) {
                List<String> extKeyUsage = getExtendedKeyUsage(cert);
                boolean hasRequiredUsage = policy.getRequiredExtendedKeyUsage().stream()
                        .anyMatch(extKeyUsage::contains);
                if (!hasRequiredUsage) {
                    errors.add(String.format("End-entity certificate lacks required extended key usage: %s",
                            policy.getRequiredExtendedKeyUsage()));
                }
            }
        }

        return errors;
    }

    private List<String> validateSignatureAlgorithms(List<X509Certificate> certificates) {
        List<String> errors = new ArrayList<>();

        for (int i = 0; i < certificates.size(); i++) {
            X509Certificate cert = certificates.get(i);
            String sigAlg = cert.getSigAlgName();

            if (WEAK_SIGNATURE_ALGORITHMS.contains(sigAlg)) {
                errors.add(String.format("Certificate %d uses weak signature algorithm: %s", i + 1, sigAlg));
            }

            if (!policy.getAllowedSignatureAlgorithms().isEmpty()) {
                if (!policy.getAllowedSignatureAlgorithms().contains(sigAlg)) {
                    errors.add(String.format("Certificate %d uses disallowed signature algorithm: %s",
                            i + 1, sigAlg));
                }
            }
        }

        return errors;
    }

    private List<String> validateChainStructure(List<X509Certificate> certificates) {
        List<String> errors = new ArrayList<>();

        for (int i = 0; i < certificates.size() - 1; i++) {
            X509Certificate current = certificates.get(i);
            X509Certificate issuer = certificates.get(i + 1);

            if (!current.getIssuerX500Principal().equals(issuer.getSubjectX500Principal())) {
                errors.add(String.format("Chain broken: certificate %d issuer does not match certificate %d subject",
                        i + 1, i + 2));
            }
        }

        X509Certificate rootCandidate = certificates.get(certificates.size() - 1);
        boolean isSelfSigned = rootCandidate.getIssuerX500Principal()
                .equals(rootCandidate.getSubjectX500Principal());

        if (!isSelfSigned && !trustStoreManager.isTrusted(rootCandidate)) {
            boolean foundInTrustStore = trustStoreManager.getTrustedCertificates().stream()
                    .anyMatch(t -> t.getSubjectX500Principal()
                            .equals(rootCandidate.getSubjectX500Principal()));
            if (!foundInTrustStore) {
                errors.add("Chain does not terminate at a trusted root certificate");
            }
        }

        return errors;
    }

    private String buildDetailedErrorMessage(CertPathValidatorException e,
                                            List<X509Certificate> certificates) {
        StringBuilder sb = new StringBuilder();
        sb.append("PKIX validation failed: ");

        BasicReason reason = e.getReason();
        if (reason != null) {
            sb.append(reason.toString());
        } else {
            sb.append(e.getMessage());
        }

        if (e.getCertPath() != null) {
            int index = e.getIndex();
            if (index >= 0 && index < certificates.size()) {
                X509Certificate cert = certificates.get(index);
                sb.append(" (at certificate: ").append(
                        truncate(cert.getSubjectX500Principal().getName(), 50)).append(")");
            }
        }

        return sb.toString();
    }

    private List<ValidationResult.CertificateInfo> extractCertInfo(List<X509Certificate> certs) {
        return certs.stream()
                .map(ValidationResult.CertificateInfo::new)
                .collect(Collectors.toList());
    }

    private List<String> getExtendedKeyUsage(X509Certificate cert) {
        try {
            List<String> extKeyUsage = cert.getExtendedKeyUsage();
            return extKeyUsage != null ? extKeyUsage : Collections.emptyList();
        } catch (CertificateException e) {
            return Collections.emptyList();
        }
    }

    private X509Certificate loadCertificate(String path)
            throws CertificateException, java.io.IOException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        java.io.File file = new java.io.File(path);

        if (path.toLowerCase().endsWith(".pem")) {
            String content = java.nio.file.Files.readString(file.toPath());
            List<X509Certificate> certs = parsePemCertificates(content);
            return certs.isEmpty() ? null : certs.get(0);
        } else {
            try (java.io.FileInputStream fis = new java.io.FileInputStream(file)) {
                return (X509Certificate) cf.generateCertificate(fis);
            }
        }
    }

    private List<X509Certificate> parsePemCertificates(String pemContent)
            throws CertificateException, java.io.IOException {
        List<X509Certificate> certificates = new ArrayList<>();
        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        String[] certBlocks = pemContent.split("-----END CERTIFICATE-----");
        for (String certBlock : certBlocks) {
            String trimmed = certBlock.trim();
            if (trimmed.isEmpty() || !trimmed.contains("-----BEGIN CERTIFICATE-----")) {
                continue;
            }

            String base64Cert = trimmed
                    .replace("-----BEGIN CERTIFICATE-----", "")
                    .replaceAll("\\s+", "");

            if (!base64Cert.isEmpty()) {
                byte[] certBytes = java.util.Base64.getDecoder().decode(base64Cert);
                X509Certificate cert = (X509Certificate) cf.generateCertificate(
                        new java.io.ByteArrayInputStream(certBytes));
                certificates.add(cert);
            }
        }

        return certificates;
    }

    private String getTrustAnchorSubject() {
        List<X509Certificate> certs = trustStoreManager.getTrustedCertificates();
        if (certs.isEmpty()) {
            return null;
        }
        return truncate(certs.get(0).getSubjectX500Principal().getName(), 80);
    }

    private String truncate(String s, int maxLen) {
        if (s == null) {
            return null;
        }
        return s.length() > maxLen ? s.substring(0, maxLen) + "..." : s;
    }
}
