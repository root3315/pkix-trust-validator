package com.pkix.validator;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResponse;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.jcajce.JcaOCSPResponseConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateRevokedException;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.TimeZone;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Performs certificate revocation checking using OCSP and CRL mechanisms.
 * Implements RFC 6960 (OCSP) and RFC 5280 (CRL) revocation status verification.
 */
public class RevocationChecker {

    private static final Logger logger = Logger.getLogger(RevocationChecker.class.getName());

    private static final int OCSP_TIMEOUT_MS = 10000;
    private static final int CRL_CACHE_VALIDITY_MS = 3600000;
    private static final String OCSP_NONCE_OID = "1.3.6.1.5.5.7.48.1.2";

    private static final int MAX_RETRIES = 3;
    private static final int INITIAL_RETRY_DELAY_MS = 1000;
    private static final double RETRY_BACKOFF_MULTIPLIER = 2.0;

    private final RevocationPolicy revocationPolicy;
    private final List<X509Certificate> trustAnchors;

    public RevocationChecker(RevocationPolicy revocationPolicy, List<X509Certificate> trustAnchors) {
        this.revocationPolicy = revocationPolicy;
        this.trustAnchors = trustAnchors != null ? trustAnchors : Collections.emptyList();
    }

    /**
     * Checks revocation status for a certificate using configured methods.
     *
     * @param certificate the certificate to check
     * @param issuerCert the issuer certificate
     * @return revocation check result
     */
    public RevocationResult checkRevocation(X509Certificate certificate, X509Certificate issuerCert) {
        List<String> errors = new ArrayList<>();

        if (revocationPolicy.isUseOcsp() && hasOcspUrl(certificate)) {
            RevocationResult ocspResult = checkOcsp(certificate, issuerCert);
            if (ocspResult.isRevoked()) {
                return ocspResult;
            }
            if (!ocspResult.isSuccess() && revocationPolicy.isRequireOcsp()) {
                return ocspResult;
            }
            if (!ocspResult.isSuccess()) {
                errors.addAll(ocspResult.getErrors());
            } else {
                return RevocationResult.success("OCSP check passed");
            }
        }

        if (revocationPolicy.isUseCrl() && hasCrlUrl(certificate)) {
            RevocationResult crlResult = checkCrl(certificate, issuerCert);
            if (crlResult.isRevoked()) {
                return crlResult;
            }
            if (!crlResult.isSuccess() && revocationPolicy.isRequireCrl()) {
                return crlResult;
            }
            if (!crlResult.isSuccess()) {
                errors.addAll(crlResult.getErrors());
            } else {
                return RevocationResult.success("CRL check passed");
            }
        }

        if (revocationPolicy.isRequireOcsp() && !revocationPolicy.isUseOcsp()) {
            errors.add("OCSP checking is required but not available");
        }

        if (revocationPolicy.isRequireCrl() && !revocationPolicy.isUseCrl()) {
            errors.add("CRL checking is required but not available");
        }

        if (!errors.isEmpty()) {
            return RevocationResult.failure(errors);
        }

        if (!revocationPolicy.isUseOcsp() && !revocationPolicy.isUseCrl()) {
            return RevocationResult.skipped("Revocation checking disabled");
        }

        return RevocationResult.skipped("No revocation checking method available");
    }

    /**
     * Performs OCSP revocation check for a certificate.
     *
     * @param certificate the certificate to check
     * @param issuerCert the issuer certificate
     * @return OCSP check result
     */
    public RevocationResult checkOcsp(X509Certificate certificate, X509Certificate issuerCert) {
        String ocspUrl = extractOcspUrl(certificate);
        if (ocspUrl == null || ocspUrl.isEmpty()) {
            return RevocationResult.failure("No OCSP responder URL found in certificate");
        }

        logger.fine("Checking OCSP responder: " + ocspUrl);

        try {
            OCSPReq ocspRequest = createOcspRequest(certificate, issuerCert);
            OCSPResp ocspResponse = sendOcspRequestWithRetry(ocspUrl, ocspRequest);

            if (ocspResponse.getStatus() != OCSPResp.SUCCESSFUL) {
                return RevocationResult.failure("OCSP responder returned status: " + ocspResponse.getStatus());
            }

            return processOcspResponse(ocspResponse, certificate, issuerCert);

        } catch (OCSPException e) {
            logger.log(Level.FINE, "OCSP exception", e);
            return RevocationResult.failure("OCSP protocol error: " + e.getMessage());
        } catch (OperatorCreationException e) {
            logger.log(Level.FINE, "Operator creation error", e);
            return RevocationResult.failure("Failed to create OCSP request: " + e.getMessage());
        } catch (IOException e) {
            logger.log(Level.FINE, "IO error during OCSP check", e);
            if (e instanceof SocketTimeoutException) {
                return RevocationResult.failure("OCSP responder timeout");
            }
            return RevocationResult.failure("Failed to communicate with OCSP responder: " + e.getMessage());
        } catch (GeneralSecurityException e) {
            logger.log(Level.FINE, "Security error during OCSP check", e);
            return RevocationResult.failure("Security error during OCSP check: " + e.getMessage());
        } catch (Exception e) {
            logger.log(Level.FINE, "Unexpected error during OCSP check", e);
            return RevocationResult.failure("Unexpected error: " + e.getMessage());
        }
    }

    /**
     * Performs CRL revocation check for a certificate.
     *
     * @param certificate the certificate to check
     * @param issuerCert the issuer certificate
     * @return CRL check result
     */
    public RevocationResult checkCrl(X509Certificate certificate, X509Certificate issuerCert) {
        String crlUrl = extractCrlUrl(certificate);
        if (crlUrl == null || crlUrl.isEmpty()) {
            return RevocationResult.failure("No CRL distribution point found in certificate");
        }

        logger.fine("Checking CRL: " + crlUrl);

        try {
            X509CRL crl = loadCrlWithRetry(crlUrl);
            if (crl == null) {
                return RevocationResult.failure("Failed to load CRL from: " + crlUrl);
            }

            if (!isCrlValid(crl)) {
                return RevocationResult.failure("CRL is expired or not yet valid");
            }

            if (!verifyCrlSignature(crl, issuerCert)) {
                return RevocationResult.failure("CRL signature verification failed");
            }

            X509CRLEntry entry = crl.getRevokedCertificate(certificate);
            if (entry != null) {
                String reason = getRevocationReason(entry);
                Date revocationDate = entry.getRevocationDate();
                return RevocationResult.revoked("Certificate revoked on " + revocationDate + ": " + reason);
            }

            return RevocationResult.success("CRL check passed - certificate not revoked");

        } catch (CRLException e) {
            logger.log(Level.FINE, "CRL exception", e);
            return RevocationResult.failure("CRL processing error: " + e.getMessage());
        } catch (IOException e) {
            logger.log(Level.FINE, "IO error during CRL check", e);
            return RevocationResult.failure("Failed to download CRL: " + e.getMessage());
        } catch (GeneralSecurityException e) {
            logger.log(Level.FINE, "Security error during CRL check", e);
            return RevocationResult.failure("CRL signature verification failed: " + e.getMessage());
        } catch (Exception e) {
            logger.log(Level.FINE, "Unexpected error during CRL check", e);
            return RevocationResult.failure("Unexpected error: " + e.getMessage());
        }
    }

    private OCSPReq createOcspRequest(X509Certificate cert, X509Certificate issuer)
            throws OCSPException, OperatorCreationException, IOException, GeneralSecurityException {

        JcaDigestCalculatorProviderBuilder digestCalcProviderBuilder = new JcaDigestCalculatorProviderBuilder();
        digestCalcProviderBuilder.setDigestProvider("SHA256");
        DigestCalculator digestCalculator = digestCalcProviderBuilder.build().get(CertificateID.HASH_SHA1);

        CertificateID certId = new CertificateID(
                digestCalculator,
                new X509CertificateHolder(issuer.getEncoded()),
                cert.getSerialNumber()
        );

        OCSPReqBuilder reqBuilder = new OCSPReqBuilder();
        reqBuilder.addRequest(certId);

        if (revocationPolicy.isIncludeOcspNonce()) {
            BigInteger nonce = BigInteger.valueOf(System.currentTimeMillis());
            reqBuilder.setRequestExtension(Extension.ocspNonce, new DEROctetString(nonce.toByteArray()));
        }

        return reqBuilder.build();
    }

    private OCSPResp sendOcspRequestWithRetry(String url, OCSPReq request) throws IOException {
        return executeWithRetry(() -> sendOcspRequest(url, request), "OCSP request to " + url);
    }

    private X509CRL loadCrlWithRetry(String crlUrl) throws IOException, CRLException {
        return executeWithRetry(() -> loadCrl(crlUrl), "CRL download from " + crlUrl);
    }

    private <T> T executeWithRetry(RetryableOperation<T> operation, String operationName) throws IOException {
        int attempt = 0;
        long delayMs = INITIAL_RETRY_DELAY_MS;
        IOException lastException = null;

        while (attempt < MAX_RETRIES) {
            attempt++;
            try {
                if (attempt > 1) {
                    logger.fine(String.format("Retry attempt %d/%d for %s", attempt, MAX_RETRIES, operationName));
                    Thread.sleep(delayMs);
                    delayMs = (long) (delayMs * RETRY_BACKOFF_MULTIPLIER);
                }
                return operation.execute();
            } catch (SocketTimeoutException e) {
                lastException = e;
                logger.fine(String.format("Timeout on attempt %d/%d for %s", attempt, MAX_RETRIES, operationName));
            } catch (IOException e) {
                lastException = e;
                if (isRetryableHttpError(e)) {
                    logger.fine(String.format("Retryable IO error on attempt %d/%d for %s: %s",
                            attempt, MAX_RETRIES, operationName, e.getMessage()));
                } else {
                    throw e;
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("Retry interrupted", e);
            }
        }

        throw new IOException("Failed after " + MAX_RETRIES + " attempts: " + lastException.getMessage(), lastException);
    }

    private boolean isRetryableHttpError(IOException e) {
        String message = e.getMessage();
        if (message == null) {
            return true;
        }
        return message.contains("500") || message.contains("502") || message.contains("503") ||
               message.contains("504") || message.contains("Service Unavailable") ||
               e instanceof SocketTimeoutException;
    }

    private OCSPResp sendOcspRequest(String url, OCSPReq request) throws IOException {
        HttpURLConnection connection = (HttpURLConnection) new URL(url).openConnection();
        connection.setConnectTimeout(OCSP_TIMEOUT_MS);
        connection.setReadTimeout(OCSP_TIMEOUT_MS);
        connection.setRequestMethod("POST");
        connection.setDoOutput(true);
        connection.setRequestProperty("Content-Type", "application/ocsp-request");
        connection.setRequestProperty("Accept", "application/ocsp-response");

        try (OutputStream os = connection.getOutputStream()) {
            os.write(request.getEncoded());
            os.flush();
        }

        int responseCode = connection.getResponseCode();
        if (responseCode != HttpURLConnection.HTTP_OK) {
            throw new IOException("OCSP responder returned HTTP " + responseCode);
        }

        try (InputStream is = connection.getInputStream()) {
            return new OCSPResp(readAllBytes(is));
        } finally {
            connection.disconnect();
        }
    }

    private byte[] readAllBytes(InputStream is) throws IOException {
        byte[] buffer = new byte[4096];
        java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
        int len;
        while ((len = is.read(buffer)) != -1) {
            baos.write(buffer, 0, len);
        }
        return baos.toByteArray();
    }

    private RevocationResult processOcspResponse(OCSPResp response, X509Certificate cert, X509Certificate issuer)
            throws OCSPException, CertificateException, OperatorCreationException {

        Object responseObj = response.getResponseObject();
        if (!(responseObj instanceof BasicOCSPResponse)) {
            return RevocationResult.failure("Invalid OCSP response format");
        }

        BasicOCSPResponse basicResponse = (BasicOCSPResponse) responseObj;
        JcaOCSPResponseConverter responseConverter = new JcaOCSPResponseConverter();

        SingleResp[] responses = basicResponse.getResponses();
        if (responses.length == 0) {
            return RevocationResult.failure("Empty OCSP response");
        }

        SingleResp singleResp = responses[0];
        Object status = singleResp.getCertStatus();

        if (status == CertificateStatus.GOOD) {
            Date thisUpdate = singleResp.getThisUpdate();
            Date nextUpdate = singleResp.getNextUpdate();

            if (!isOcspResponseValid(thisUpdate, nextUpdate)) {
                return RevocationResult.failure("OCSP response is expired or not yet valid");
            }

            return RevocationResult.success("OCSP check passed - certificate status is GOOD");
        } else if (status instanceof RevokedStatus) {
            RevokedStatus revokedStatus = (RevokedStatus) status;
            String reason = getRevocationReasonName(revokedStatus.getRevocationReason());
            return RevocationResult.revoked("Certificate revoked via OCSP: " + reason);
        } else if (status instanceof CertificateStatus.Unknown) {
            return RevocationResult.failure("Certificate status unknown to OCSP responder");
        }

        return RevocationResult.skipped("OCSP response status unclear");
    }

    private boolean isOcspResponseValid(Date thisUpdate, Date nextUpdate) {
        Instant now = Instant.now();

        if (thisUpdate != null && now.isBefore(thisUpdate.toInstant())) {
            logger.warning("OCSP thisUpdate is in the future");
            return false;
        }

        if (nextUpdate != null && now.isAfter(nextUpdate.toInstant())) {
            logger.warning("OCSP response has expired");
            return false;
        }

        return true;
    }

    private X509CRL loadCrl(String crlUrl) throws IOException, CRLException {
        URL url = new URL(crlUrl);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setConnectTimeout(OCSP_TIMEOUT_MS);
        connection.setReadTimeout(OCSP_TIMEOUT_MS);
        connection.setRequestMethod("GET");

        int responseCode = connection.getResponseCode();
        if (responseCode != HttpURLConnection.HTTP_OK) {
            throw new IOException("CRL download returned HTTP " + responseCode);
        }

        try (InputStream is = connection.getInputStream()) {
            java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance("X.509");
            return (X509CRL) cf.generateCRL(is);
        } finally {
            connection.disconnect();
        }
    }

    private boolean isCrlValid(X509CRL crl) {
        Instant now = Instant.now();
        Date thisUpdate = crl.getThisUpdate();
        Date nextUpdate = crl.getNextUpdate();

        if (thisUpdate != null && now.isBefore(thisUpdate.toInstant())) {
            return false;
        }

        if (nextUpdate != null && now.isAfter(nextUpdate.toInstant())) {
            return false;
        }

        return true;
    }

    private boolean verifyCrlSignature(X509CRL crl, X509Certificate issuerCert)
            throws GeneralSecurityException {
        try {
            crl.verify(issuerCert.getPublicKey());
            return true;
        } catch (GeneralSecurityException e) {
            logger.log(Level.FINE, "CRL signature verification failed", e);
            throw e;
        }
    }

    private String extractOcspUrl(X509Certificate cert) {
        try {
            byte[] extValue = cert.getExtensionValue(Extension.authorityInfoAccess.getId());
            if (extValue == null) {
                return null;
            }

            ASN1Primitive asn1 = decodeExtensionValue(extValue);
            if (!(asn1 instanceof ASN1Sequence)) {
                return null;
            }

            ASN1Sequence seq = (ASN1Sequence) asn1;
            for (ASN1Encodable element : seq) {
                if (element instanceof ASN1Sequence) {
                    ASN1Sequence accessDesc = (ASN1Sequence) element;
                    if (accessDesc.size() >= 2) {
                        ASN1Encodable accessMethod = accessDesc.getObjectAt(0);
                        ASN1Encodable accessLocation = accessDesc.getObjectAt(1);

                        if (isOcspAccessMethod(accessMethod)) {
                            return extractUrlFromGeneralName(accessLocation);
                        }
                    }
                }
            }
        } catch (IOException e) {
            logger.log(Level.FINE, "Failed to extract OCSP URL", e);
        }

        return null;
    }

    private String extractCrlUrl(X509Certificate cert) {
        try {
            byte[] extValue = cert.getExtensionValue(Extension.cRLDistributionPoints.getId());
            if (extValue == null) {
                return null;
            }

            ASN1Primitive asn1 = decodeExtensionValue(extValue);
            if (!(asn1 instanceof ASN1Sequence)) {
                return null;
            }

            ASN1Sequence seq = (ASN1Sequence) asn1;
            for (ASN1Encodable element : seq) {
                if (element instanceof ASN1Sequence) {
                    ASN1Sequence dpSeq = (ASN1Sequence) element;
                    for (ASN1Encodable dpElement : dpSeq) {
                        if (dpElement instanceof ASN1TaggedObject) {
                            ASN1TaggedObject tagged = (ASN1TaggedObject) dpElement;
                            if (tagged.getTagNo() == 0) {
                                ASN1Primitive dpName = ASN1Primitive.fromByteArray(tagged.getOctets());
                                if (dpName instanceof ASN1Sequence) {
                                    ASN1Sequence fullNameSeq = (ASN1Sequence) dpName;
                                    for (ASN1Encodable name : fullNameSeq) {
                                        if (name instanceof ASN1TaggedObject) {
                                            ASN1TaggedObject nameTagged = (ASN1TaggedObject) name;
                                            if (nameTagged.getTagNo() == 6) {
                                                return new String(
                                                        ASN1OctetString.getInstance(nameTagged.getOctets()).getOctets(),
                                                        java.nio.charset.StandardCharsets.US_ASCII
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        } catch (IOException e) {
            logger.log(Level.FINE, "Failed to extract CRL URL", e);
        }

        return null;
    }

    private boolean hasOcspUrl(X509Certificate cert) {
        return extractOcspUrl(cert) != null;
    }

    private boolean hasCrlUrl(X509Certificate cert) {
        return extractCrlUrl(cert) != null;
    }

    private boolean isOcspAccessMethod(ASN1Encodable accessMethod) {
        if (!(accessMethod instanceof ASN1Primitive)) {
            return false;
        }
        try {
            org.bouncycastle.asn1.ASN1ObjectIdentifier oid =
                    org.bouncycastle.asn1.ASN1ObjectIdentifier.getInstance((ASN1Primitive) accessMethod);
            return oid.getId().equals("1.3.6.1.5.5.7.48.1");
        } catch (IOException e) {
            return false;
        }
    }

    private String extractUrlFromGeneralName(ASN1Encodable accessLocation) {
        if (accessLocation instanceof ASN1TaggedObject) {
            ASN1TaggedObject tagged = (ASN1TaggedObject) accessLocation;
            if (tagged.getTagNo() == GeneralName.uniformResourceIdentifier) {
                try {
                    DEROctetString octetString = DEROctetString.getInstance(tagged.getOctets());
                    return new String(octetString.getOctets(), java.nio.charset.StandardCharsets.US_ASCII);
                } catch (Exception e) {
                    logger.log(Level.FINE, "Failed to extract URL", e);
                }
            }
        }
        return null;
    }

    private ASN1Primitive decodeExtensionValue(byte[] extValue) throws IOException {
        ASN1OctetString octetString = ASN1OctetString.getInstance(extValue);
        try (ASN1InputStream ais = new ASN1InputStream(octetString.getOctets())) {
            return ais.readObject();
        }
    }

    private String getRevocationReason(X509CRLEntry entry) {
        int reasonCode = entry.getRevocationReason();
        return getRevocationReasonName(reasonCode);
    }

    private String getRevocationReasonName(int reasonCode) {
        switch (reasonCode) {
            case CRLReason.unspecified: return "unspecified";
            case CRLReason.keyCompromise: return "key compromise";
            case CRLReason.cACompromise: return "CA compromise";
            case CRLReason.affiliationChanged: return "affiliation changed";
            case CRLReason.superseded: return "superseded";
            case CRLReason.cessationOfOperation: return "cessation of operation";
            case CRLReason.certificateHold: return "certificate hold";
            case CRLReason.privilegeWithdrawn: return "privilege withdrawn";
            case CRLReason.aACompromise: return "AA compromise";
            default: return "unknown (" + reasonCode + ")";
        }
    }

    @FunctionalInterface
    private interface RetryableOperation<T> {
        T execute() throws IOException;
    }

    /**
     * Revocation checking policy configuration.
     */
    public static class RevocationPolicy {
        private final boolean useOcsp;
        private final boolean useCrl;
        private final boolean requireOcsp;
        private final boolean requireCrl;
        private final boolean includeOcspNonce;
        private final boolean softFail;

        private RevocationPolicy(Builder builder) {
            this.useOcsp = builder.useOcsp;
            this.useCrl = builder.useCrl;
            this.requireOcsp = builder.requireOcsp;
            this.requireCrl = builder.requireCrl;
            this.includeOcspNonce = builder.includeOcspNonce;
            this.softFail = builder.softFail;
        }

        public boolean isUseOcsp() { return useOcsp; }
        public boolean isUseCrl() { return useCrl; }
        public boolean isRequireOcsp() { return requireOcsp; }
        public boolean isRequireCrl() { return requireCrl; }
        public boolean isIncludeOcspNonce() { return includeOcspNonce; }
        public boolean isSoftFail() { return softFail; }

        public static Builder builder() {
            return new Builder();
        }

        public static RevocationPolicy defaultPolicy() {
            return builder().build();
        }

        public static final class Builder {
            private boolean useOcsp = true;
            private boolean useCrl = true;
            private boolean requireOcsp = false;
            private boolean requireCrl = false;
            private boolean includeOcspNonce = true;
            private boolean softFail = true;

            public Builder useOcsp(boolean useOcsp) {
                this.useOcsp = useOcsp;
                return this;
            }

            public Builder useCrl(boolean useCrl) {
                this.useCrl = useCrl;
                return this;
            }

            public Builder requireOcsp(boolean requireOcsp) {
                this.requireOcsp = requireOcsp;
                return this;
            }

            public Builder requireCrl(boolean requireCrl) {
                this.requireCrl = requireCrl;
                return this;
            }

            public Builder includeOcspNonce(boolean includeOcspNonce) {
                this.includeOcspNonce = includeOcspNonce;
                return this;
            }

            public Builder softFail(boolean softFail) {
                this.softFail = softFail;
                return this;
            }

            public RevocationPolicy build() {
                return new RevocationPolicy(this);
            }
        }
    }

    /**
     * Result of a revocation check operation.
     */
    public static class RevocationResult {
        private final Status status;
        private final String message;
        private final List<String> errors;
        private final Instant checkTimestamp;

        public enum Status {
            SUCCESS,
            REVOKED,
            FAILURE,
            SKIPPED
        }

        private RevocationResult(Status status, String message, List<String> errors) {
            this.status = status;
            this.message = message;
            this.errors = Collections.unmodifiableList(new ArrayList<>(errors));
            this.checkTimestamp = Instant.now();
        }

        public static RevocationResult success(String message) {
            return new RevocationResult(Status.SUCCESS, message, Collections.emptyList());
        }

        public static RevocationResult revoked(String message) {
            return new RevocationResult(Status.REVOKED, message, Collections.emptyList());
        }

        public static RevocationResult failure(String error) {
            return new RevocationResult(Status.FAILURE, "Revocation check failed",
                    Collections.singletonList(error));
        }

        public static RevocationResult failure(List<String> errors) {
            return new RevocationResult(Status.FAILURE, "Revocation check failed", errors);
        }

        public static RevocationResult skipped(String message) {
            return new RevocationResult(Status.SKIPPED, message, Collections.emptyList());
        }

        public Status getStatus() { return status; }
        public String getMessage() { return message; }
        public List<String> getErrors() { return errors; }
        public Instant getCheckTimestamp() { return checkTimestamp; }

        public boolean isSuccess() { return status == Status.SUCCESS; }
        public boolean isRevoked() { return status == Status.REVOKED; }
        public boolean isFailure() { return status == Status.FAILURE; }
        public boolean isSkipped() { return status == Status.SKIPPED; }

        @Override
        public String toString() {
            return "RevocationResult{status=" + status + ", message='" + message + "'}";
        }
    }
}
