package com.pkix.validator;

import java.security.cert.CertPathValidatorException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Immutable result container for certificate chain validation operations.
 * Captures validation status, failure reasons, and certificate metadata
 * for comprehensive audit trails and debugging.
 */
public final class ValidationResult {

    private final boolean valid;
    private final String statusMessage;
    private final List<String> validationErrors;
    private final List<CertificateInfo> certificateChain;
    private final Instant validationTimestamp;
    private final String trustAnchor;
    private final ValidationPolicy appliedPolicy;

    /**
     * Creates a successful validation result.
     *
     * @param certificateChain the validated certificate chain information
     * @param trustAnchor the trusted root certificate subject
     * @param policy the validation policy that was applied
     * @return a valid ValidationResult instance
     */
    public static ValidationResult success(
            List<CertificateInfo> certificateChain,
            String trustAnchor,
            ValidationPolicy policy) {
        return new ValidationResult(true, "Certificate chain validated successfully",
                Collections.emptyList(), certificateChain, trustAnchor, policy);
    }

    /**
     * Creates a failed validation result with errors.
     *
     * @param errors list of validation error messages
     * @param certificateChain the certificate chain that failed validation
     * @param trustAnchor the attempted trust anchor
     * @param policy the validation policy that was applied
     * @return an invalid ValidationResult instance
     */
    public static ValidationResult failure(
            List<String> errors,
            List<CertificateInfo> certificateChain,
            String trustAnchor,
            ValidationPolicy policy) {
        return new ValidationResult(false, "Certificate chain validation failed",
                errors, certificateChain, trustAnchor, policy);
    }

    /**
     * Creates a failed validation result with a single error.
     *
     * @param error the validation error message
     * @param policy the validation policy that was applied
     * @return an invalid ValidationResult instance
     */
    public static ValidationResult failure(String error, ValidationPolicy policy) {
        return new ValidationResult(false, "Certificate chain validation failed",
                Collections.singletonList(error), Collections.emptyList(), null, policy);
    }

    private ValidationResult(boolean valid, String statusMessage, List<String> validationErrors,
                             List<CertificateInfo> certificateChain, String trustAnchor,
                             ValidationPolicy policy) {
        this.valid = valid;
        this.statusMessage = Objects.requireNonNull(statusMessage);
        this.validationErrors = Collections.unmodifiableList(new ArrayList<>(validationErrors));
        this.certificateChain = certificateChain != null ?
                Collections.unmodifiableList(new ArrayList<>(certificateChain)) :
                Collections.emptyList();
        this.validationTimestamp = Instant.now();
        this.trustAnchor = trustAnchor;
        this.appliedPolicy = Objects.requireNonNull(policy);
    }

    /**
     * Returns whether the certificate chain validation succeeded.
     *
     * @return true if validation passed, false otherwise
     */
    public boolean isValid() {
        return valid;
    }

    /**
     * Returns the human-readable status message.
     *
     * @return status message describing the validation outcome
     */
    public String getStatusMessage() {
        return statusMessage;
    }

    /**
     * Returns the list of validation errors encountered.
     *
     * @return unmodifiable list of error messages
     */
    public List<String> getValidationErrors() {
        return validationErrors;
    }

    /**
     * Returns information about each certificate in the validated chain.
     *
     * @return unmodifiable list of certificate information
     */
    public List<CertificateInfo> getCertificateChain() {
        return certificateChain;
    }

    /**
     * Returns the timestamp when validation was performed.
     *
     * @return validation timestamp
     */
    public Instant getValidationTimestamp() {
        return validationTimestamp;
    }

    /**
     * Returns the subject of the trust anchor used for validation.
     *
     * @return trust anchor subject DN, or null if validation failed early
     */
    public String getTrustAnchor() {
        return trustAnchor;
    }

    /**
     * Returns the validation policy that was applied.
     *
     * @return the applied validation policy
     */
    public ValidationPolicy getAppliedPolicy() {
        return appliedPolicy;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("ValidationResult{valid=").append(valid);
        sb.append(", statusMessage='").append(statusMessage).append('\'');
        if (!validationErrors.isEmpty()) {
            sb.append(", errors=").append(validationErrors.size());
        }
        if (!certificateChain.isEmpty()) {
            sb.append(", chainLength=").append(certificateChain.size());
        }
        sb.append('}');
        return sb.toString();
    }

    /**
     * Immutable container for individual certificate metadata.
     */
    public static final class CertificateInfo {
        private final String subjectDN;
        private final String issuerDN;
        private final String serialNumber;
        private final Instant notBefore;
        private final Instant notAfter;
        private final String signatureAlgorithm;
        private final int version;
        private final boolean isCA;
        private final List<String> keyUsage;
        private final List<String> extendedKeyUsage;

        public CertificateInfo(X509Certificate cert) {
            this.subjectDN = cert.getSubjectX500Principal().getName();
            this.issuerDN = cert.getIssuerX500Principal().getName();
            this.serialNumber = cert.getSerialNumber().toString(16).toUpperCase();
            this.notBefore = cert.getNotBefore().toInstant();
            this.notAfter = cert.getNotAfter().toInstant();
            this.signatureAlgorithm = cert.getSigAlgName();
            this.version = cert.getVersion();
            this.isCA = cert.getBasicConstraints() >= 0;
            this.keyUsage = extractKeyUsage(cert);
            this.extendedKeyUsage = extractExtendedKeyUsage(cert);
        }

        private List<String> extractKeyUsage(X509Certificate cert) {
            List<String> usages = new ArrayList<>();
            boolean[] keyUsage = cert.getKeyUsage();
            if (keyUsage != null) {
                String[] usageNames = {
                    "digitalSignature", "nonRepudiation", "keyEncipherment",
                    "dataEncipherment", "keyAgreement", "keyCertSign",
                    "cRLSign", "encipherOnly", "decipherOnly"
                };
                for (int i = 0; i < Math.min(keyUsage.length, usageNames.length); i++) {
                    if (keyUsage[i]) {
                        usages.add(usageNames[i]);
                    }
                }
            }
            return Collections.unmodifiableList(usages);
        }

        private List<String> extractExtendedKeyUsage(X509Certificate cert) {
            List<String> usages = new ArrayList<>();
            try {
                List<String> extKeyUsage = cert.getExtendedKeyUsage();
                if (extKeyUsage != null) {
                    usages.addAll(extKeyUsage);
                }
            } catch (CertPathValidatorException e) {
                // Extended key usage not available
            }
            return Collections.unmodifiableList(usages);
        }

        public String getSubjectDN() {
            return subjectDN;
        }

        public String getIssuerDN() {
            return issuerDN;
        }

        public String getSerialNumber() {
            return serialNumber;
        }

        public Instant getNotBefore() {
            return notBefore;
        }

        public Instant getNotAfter() {
            return notAfter;
        }

        public String getSignatureAlgorithm() {
            return signatureAlgorithm;
        }

        public int getVersion() {
            return version;
        }

        public boolean isCA() {
            return isCA;
        }

        public List<String> getKeyUsage() {
            return keyUsage;
        }

        public List<String> getExtendedKeyUsage() {
            return extendedKeyUsage;
        }

        @Override
        public String toString() {
            return String.format("CertificateInfo{subject='%s', issuer='%s', serial=%s, isCA=%b}",
                    truncate(subjectDN, 50), truncate(issuerDN, 50), serialNumber, isCA);
        }

        private String truncate(String s, int maxLen) {
            return s.length() > maxLen ? s.substring(0, maxLen) + "..." : s;
        }
    }

    /**
     * Validation policy configuration for certificate chain validation.
     */
    public static final class ValidationPolicy {
        private final boolean checkRevocation;
        private final boolean requireTimestampValidity;
        private final boolean enforceKeyUsage;
        private final int maxChainLength;
        private final List<String> allowedSignatureAlgorithms;
        private final List<String> requiredExtendedKeyUsage;

        private ValidationPolicy(Builder builder) {
            this.checkRevocation = builder.checkRevocation;
            this.requireTimestampValidity = builder.requireTimestampValidity;
            this.enforceKeyUsage = builder.enforceKeyUsage;
            this.maxChainLength = builder.maxChainLength;
            this.allowedSignatureAlgorithms = Collections.unmodifiableList(
                    new ArrayList<>(builder.allowedSignatureAlgorithms));
            this.requiredExtendedKeyUsage = Collections.unmodifiableList(
                    new ArrayList<>(builder.requiredExtendedKeyUsage));
        }

        public boolean isCheckRevocation() {
            return checkRevocation;
        }

        public boolean isRequireTimestampValidity() {
            return requireTimestampValidity;
        }

        public boolean isEnforceKeyUsage() {
            return enforceKeyUsage;
        }

        public int getMaxChainLength() {
            return maxChainLength;
        }

        public List<String> getAllowedSignatureAlgorithms() {
            return allowedSignatureAlgorithms;
        }

        public List<String> getRequiredExtendedKeyUsage() {
            return requiredExtendedKeyUsage;
        }

        public static Builder builder() {
            return new Builder();
        }

        public static ValidationPolicy defaultPolicy() {
            return builder().build();
        }

        public static final class Builder {
            private boolean checkRevocation = false;
            private boolean requireTimestampValidity = true;
            private boolean enforceKeyUsage = true;
            private int maxChainLength = 10;
            private List<String> allowedSignatureAlgorithms = new ArrayList<>();
            private List<String> requiredExtendedKeyUsage = new ArrayList<>();

            public Builder checkRevocation(boolean checkRevocation) {
                this.checkRevocation = checkRevocation;
                return this;
            }

            public Builder requireTimestampValidity(boolean requireTimestampValidity) {
                this.requireTimestampValidity = requireTimestampValidity;
                return this;
            }

            public Builder enforceKeyUsage(boolean enforceKeyUsage) {
                this.enforceKeyUsage = enforceKeyUsage;
                return this;
            }

            public Builder maxChainLength(int maxChainLength) {
                this.maxChainLength = maxChainLength;
                return this;
            }

            public Builder allowedSignatureAlgorithms(List<String> algorithms) {
                this.allowedSignatureAlgorithms = new ArrayList<>(algorithms);
                return this;
            }

            public Builder requiredExtendedKeyUsage(List<String> keyUsage) {
                this.requiredExtendedKeyUsage = new ArrayList<>(keyUsage);
                return this;
            }

            public ValidationPolicy build() {
                return new ValidationPolicy(this);
            }
        }
    }
}
