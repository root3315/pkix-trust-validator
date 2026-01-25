package com.pkix.validator;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Manages trust stores for certificate validation operations.
 * Supports loading trust anchors from JKS, PKCS12, and PEM files,
 * as well as the default JVM cacerts trust store.
 */
public class TrustStoreManager {

    private static final Logger logger = Logger.getLogger(TrustStoreManager.class.getName());

    private final KeyStore trustStore;
    private final String trustStorePath;
    private final List<X509Certificate> loadedCertificates;

    /**
     * Creates a TrustStoreManager using the default JVM cacerts.
     *
     * @throws TrustStoreException if the default trust store cannot be loaded
     */
    public TrustStoreManager() throws TrustStoreException {
        this(null, null, null);
    }

    /**
     * Creates a TrustStoreManager with a custom trust store file.
     *
     * @param trustStorePath path to the trust store file
     * @param storeType the KeyStore type (e.g., "JKS", "PKCS12")
     * @param password the trust store password
     * @throws TrustStoreException if the trust store cannot be loaded
     */
    public TrustStoreManager(String trustStorePath, String storeType, char[] password)
            throws TrustStoreException {
        this.trustStorePath = trustStorePath;
        this.loadedCertificates = new ArrayList<>();

        try {
            String type = storeType != null ? storeType : KeyStore.getDefaultType();
            trustStore = KeyStore.getInstance(type);

            if (trustStorePath == null || trustStorePath.isEmpty()) {
                loadDefaultTrustStore(trustStore);
            } else {
                loadCustomTrustStore(trustStore, trustStorePath, password);
            }

            extractCertificates(trustStore);
            logger.info("Loaded " + loadedCertificates.size() + " trusted certificates");

        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
            throw new TrustStoreException("Failed to initialize trust store: " + e.getMessage(), e);
        }
    }

    /**
     * Creates a TrustStoreManager from a PEM file containing one or more certificates.
     *
     * @param pemPath path to the PEM file
     * @throws TrustStoreException if the PEM file cannot be loaded
     */
    public static TrustStoreManager fromPemFile(String pemPath) throws TrustStoreException {
        try {
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(null, null);

            String pemContent = Files.readString(Path.of(pemPath));
            List<X509Certificate> certs = parsePemCertificates(pemContent);

            int index = 0;
            for (X509Certificate cert : certs) {
                String alias = "cert-" + index++;
                ks.setCertificateEntry(alias, cert);
            }

            TrustStoreManager manager = new TrustStoreManager();
            manager.trustStore = ks;
            manager.loadedCertificates.clear();
            manager.loadedCertificates.addAll(certs);
            manager.trustStorePath = pemPath;

            return manager;

        } catch (Exception e) {
            throw new TrustStoreException("Failed to load PEM file: " + e.getMessage(), e);
        }
    }

    private void loadDefaultTrustStore(KeyStore ks) throws Exception {
        String javaHome = System.getProperty("java.home");
        String defaultTrustStore = javaHome + "/lib/security/cacerts";

        File defaultFile = new File(defaultTrustStore);
        if (defaultFile.exists()) {
            try (FileInputStream fis = new FileInputStream(defaultFile)) {
                ks.load(fis, "changeit".toCharArray());
            }
        } else {
            ks.load(null, null);
            logger.warning("Default cacerts file not found, using empty trust store");
        }
    }

    private void loadCustomTrustStore(KeyStore ks, String path, char[] password)
            throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException {
        File trustStoreFile = new File(path);
        if (!trustStoreFile.exists()) {
            throw new TrustStoreException("Trust store file not found: " + path);
        }

        try (FileInputStream fis = new FileInputStream(trustStoreFile)) {
            ks.load(fis, password != null ? password : new char[0]);
        }
    }

    private void extractCertificates(KeyStore ks) throws KeyStoreException {
        Enumeration<String> aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (ks.isCertificateEntry(alias)) {
                X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
                if (cert != null) {
                    loadedCertificates.add(cert);
                }
            }
        }
    }

    private List<X509Certificate> parsePemCertificates(String pemContent)
            throws CertificateException, IOException {
        List<X509Certificate> certificates = new ArrayList<>();

        String[] certBlocks = pemContent.split("-----END CERTIFICATE-----");
        java.security.cert.CertificateFactory cf =
                java.security.cert.CertificateFactory.getInstance("X.509");

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

    /**
     * Returns the underlying KeyStore instance.
     *
     * @return the KeyStore containing trusted certificates
     */
    public KeyStore getKeyStore() {
        return trustStore;
    }

    /**
     * Returns all trusted certificates as X509Certificate objects.
     *
     * @return unmodifiable list of trusted certificates
     */
    public List<X509Certificate> getTrustedCertificates() {
        return Collections.unmodifiableList(loadedCertificates);
    }

    /**
     * Checks if a certificate is present in the trust store.
     *
     * @param certificate the certificate to check
     * @return true if the certificate is trusted
     */
    public boolean isTrusted(X509Certificate certificate) {
        try {
            for (X509Certificate trusted : loadedCertificates) {
                if (trusted.equals(certificate)) {
                    return true;
                }
            }
            return false;
        } catch (Exception e) {
            logger.log(Level.FINE, "Error checking trust", e);
            return false;
        }
    }

    /**
     * Returns the path to the trust store file.
     *
     * @return trust store path, or null if using default
     */
    public String getTrustStorePath() {
        return trustStorePath;
    }

    /**
     * Returns the number of trusted certificates loaded.
     *
     * @return count of trusted certificates
     */
    public int getTrustedCertificateCount() {
        return loadedCertificates.size();
    }

    /**
     * Exception thrown when trust store operations fail.
     */
    public static class TrustStoreException extends Exception {
        public TrustStoreException(String message) {
            super(message);
        }

        public TrustStoreException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
