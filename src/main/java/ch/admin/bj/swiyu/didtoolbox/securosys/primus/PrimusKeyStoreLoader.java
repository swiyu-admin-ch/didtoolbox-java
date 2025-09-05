package ch.admin.bj.swiyu.didtoolbox.securosys.primus;

import lombok.AccessLevel;
import lombok.Getter;

import java.io.*;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Properties;

/**
 * This class represents a Securosys Primus HSM-based storage facility for cryptographic keys and certificates.
 * <p>
 * The required credentials may be supplied either from the system environment or a property file.
 * <p>
 * CAUTION The relevant JCE security provider library ("Securosys JCE provider for Securosys Primus HSM")
 * is expected to be in the <code>CLASSPATH</code>. The library must feature a provider implementation class
 * <code>com.securosys.primus.jce.PrimusProvider</code>.
 */
public class PrimusKeyStoreLoader {

    final public static String PROVIDER_CLASS = "com.securosys.primus.jce.PrimusProvider";
    final private static String KEY_STORE_TYPE_GETTER = "getKeyStoreTypeName";
    final private static String PROVIDER_NAME_GETTER = "getProviderName";
    @Getter(AccessLevel.PACKAGE)
    final private KeyStore keyStore;

    /**
     * The empty constructor.
     * <p>
     * CAUTION This constructor does not make any attempt to load the keystore, as no transport configuration is known at the time.
     * Use other constructors for the purpose.
     *
     * @throws PrimusKeyStoreInitializationException
     */
    public PrimusKeyStoreLoader() throws PrimusKeyStoreInitializationException {
        try {
            // Add Securosys JCE provider for Securosys Primus HSM ("SecurosysPrimusXSeries") via reflection
            var cls = Class.forName(PROVIDER_CLASS);
            var primusProvider = (Provider) cls.getDeclaredConstructor().newInstance();

            Security.addProvider(primusProvider);

            // This JCE provider also able to deliver the correct type that should be used to instantiate java.security.KeyStore object
            // (encapsulating the KeyStoreSpi implementation)
            var type = (String) cls.getDeclaredMethod(KEY_STORE_TYPE_GETTER).invoke(primusProvider);

            var providerName = (String) cls.getDeclaredMethod(PROVIDER_NAME_GETTER).invoke(primusProvider);

            // Throws: KeyStoreException – if no provider supports a KeyStoreSpi implementation for the specified type
            //                             (it is the same as checking primusProvider.getService("KeyStore", KEY_STORE_TYPE) against null)
            //         NullPointerException – if type is null
            this.keyStore = KeyStore.getInstance(type, providerName);

            // CAUTION Needless to say, calling this.keyStore.load(null) at this point would cause:
            //         com.securosys.primus.jce.transport.TransportUnconfiguredException: transport configuration not yet set

        } catch (Exception e) {
            throw new PrimusKeyStoreInitializationException(
                    "Failed to initialize Securosys Primus Key Store. Ensure the required lib/primusX-java[8|11].jar libraries exist on the system", e);
        }
    }

    /**
     * The constructor capable of loading credentials from the system environment.
     * The relevant envvars are described by {@link SecurosysPrimusEnvironment}.
     * <p>
     * If supplied, credentials may also be loaded from a file, as fallback to system environment variables.
     *
     * @param credentials
     * @throws CertificateException
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws PrimusKeyStoreInitializationException
     */
    public PrimusKeyStoreLoader(File credentials)
            throws CertificateException, IOException, NoSuchAlgorithmException, PrimusKeyStoreInitializationException {

        this();

        Properties props = null;
        if (credentials != null) {
            props = new Properties();
            props.load(Files.newInputStream(credentials.toPath()));
        }

        var host = System.getenv(SecurosysPrimusEnvironment.SECUROSYS_PRIMUS_HOST.name());
        if (host == null && props != null) {
            host = props.getProperty(SecurosysPrimusEnvironment.SECUROSYS_PRIMUS_HOST.toProperty());
        }
        if (host == null) {
            throw new IOException("Securosys Primus HSM host cannot be resolved. "
                    + "You may supply it either via property file or by setting the relevant system environment variable: "
                    + SecurosysPrimusEnvironment.SECUROSYS_PRIMUS_HOST.name());
        }

        var portAsString = System.getenv(SecurosysPrimusEnvironment.SECUROSYS_PRIMUS_PORT.name());
        if (portAsString == null && props != null) {
            portAsString = props.getProperty(SecurosysPrimusEnvironment.SECUROSYS_PRIMUS_PORT.toProperty());
        }
        var port = -1;
        try {
            if (portAsString != null) {
                port = Short.parseShort(portAsString);
            }
        } catch (NumberFormatException ignored) {
            throw new IOException("Securosys Primus HSM port is invalid.");
        }
        if (port < 0) {
            throw new IOException("Securosys Primus HSM port cannot be resolved. "
                    + "You may supply it either via property file or by setting the relevant system environment variable: "
                    + SecurosysPrimusEnvironment.SECUROSYS_PRIMUS_PORT.name());
        }

        var user = System.getenv(SecurosysPrimusEnvironment.SECUROSYS_PRIMUS_USER.name());
        if (user == null && props != null) {
            user = props.getProperty(SecurosysPrimusEnvironment.SECUROSYS_PRIMUS_USER.toProperty());
        }
        if (user == null) {
            throw new IOException("Securosys Primus HSM user cannot be resolved. "
                    + "You may supply it either via property file or by setting the relevant system environment variable: "
                    + SecurosysPrimusEnvironment.SECUROSYS_PRIMUS_USER.name());
        }

        var password = System.getenv(SecurosysPrimusEnvironment.SECUROSYS_PRIMUS_PASSWORD.name());
        if (password == null && props != null) {
            password = props.getProperty(SecurosysPrimusEnvironment.SECUROSYS_PRIMUS_PASSWORD.toProperty());
        }
        if (password == null) {
            throw new IOException("Securosys Primus HSM password cannot be resolved. "
                    + "You may supply it either via property file or by setting the relevant system environment variable: "
                    + SecurosysPrimusEnvironment.SECUROSYS_PRIMUS_PASSWORD.name());
        }

        // Throws: IOException – if there is an I/O or format problem with the keystore data, if a password is required but not given,
        //                       or if the given password was incorrect. If the error is due to a wrong password,
        //                       the cause of the IOException should be an UnrecoverableKeyException
        //         NoSuchAlgorithmException – if the algorithm used to check the integrity of the keystore cannot be found
        //         CertificateException – if any of the certificates in the keystore could not be loaded
        this.keyStore.load(SecurosysPrimusEnvironment.toStream(host, port, user, password), null);
    }

    public PrimusKeyStoreLoader(String host,
                                int port,
                                String user,
                                String password)
            throws CertificateException, IOException, NoSuchAlgorithmException, PrimusKeyStoreInitializationException {

        this();

        // Throws: IOException – if there is an I/O or format problem with the keystore data, if a password is required but not given,
        //                       or if the given password was incorrect. If the error is due to a wrong password,
        //                       the cause of the IOException should be an UnrecoverableKeyException
        //         NoSuchAlgorithmException – if the algorithm used to check the integrity of the keystore cannot be found
        //         CertificateException – if any of the certificates in the keystore could not be loaded
        this.keyStore.load(SecurosysPrimusEnvironment.toStream(host, port, user, password), null);
    }

    /**
     * The system envvars storing the credentials required to load Securosys Primus Key Store.
     */
    public enum SecurosysPrimusEnvironment {
        SECUROSYS_PRIMUS_HOST, SECUROSYS_PRIMUS_PORT, SECUROSYS_PRIMUS_USER, SECUROSYS_PRIMUS_PASSWORD;

        /**
         * Assembles a (byte) stream suitable for feeding (directly) into Primus' keystore.
         */
        static InputStream toStream(String host,
                                    int port,
                                    String user,
                                    String password) {

            // ad-hoc configuration - assemble a byte stream to feed into Primus' keystore
            final var baos = new ByteArrayOutputStream();
            (new PrintStream(baos)).println(
                    SecurosysPrimusEnvironment.SECUROSYS_PRIMUS_HOST.toCredentialFileLine(host) + // Primus Proxy
                            SecurosysPrimusEnvironment.SECUROSYS_PRIMUS_PORT.toCredentialFileLine(Integer.toString(port)) + // Primus Proxy TCP port
                            SecurosysPrimusEnvironment.SECUROSYS_PRIMUS_USER.toCredentialFileLine(user) + // Primus HSM user
                            SecurosysPrimusEnvironment.SECUROSYS_PRIMUS_PASSWORD.toCredentialFileLine(password) // Primus HSM password
            );

            return new ByteArrayInputStream(baos.toByteArray());
        }

        private String toProperty() {
            return this.name().toLowerCase();
        }

        private String toCredentialFileLine(String value) {
            if (this == SECUROSYS_PRIMUS_HOST) {
                return "com.securosys.primus.jce.credentials.host=" + value + System.lineSeparator();
            } else if (this == SECUROSYS_PRIMUS_PORT) {
                return "com.securosys.primus.jce.credentials.port=" + value + System.lineSeparator();
            } else if (this == SECUROSYS_PRIMUS_USER) {
                return "com.securosys.primus.jce.credentials.user=" + value + System.lineSeparator();
            } else if (this == SECUROSYS_PRIMUS_PASSWORD) {
                return "com.securosys.primus.jce.credentials.password=" + value + System.lineSeparator();
            }

            throw new RuntimeException("The envvar " + this.name() + " is not required as credential for a Securosys Primus Key Store.");
        }
    }

    /**
     * Loads a key (pair) from the underlying Primus key store. The key is associated with the given {@code alias},
     * using the given {@code password} to recover it.
     *
     * @param alias    the alias name
     * @param password the password for recovering the key
     * @return the requested key, or {@code null} if the given {@code alias} does not exist or does not identify a key-related entry.
     * @throws UnrecoverableEntryException
     * @throws KeyStoreException
     * @throws NoSuchAlgorithmException
     * @throws KeyException
     */
    KeyPair loadKeyPair(String alias, String password)
            throws UnrecoverableEntryException, KeyStoreException, NoSuchAlgorithmException, KeyException {

        var keyStore = this.getKeyStore();

        if (!keyStore.isKeyEntry(alias)) {
            throw new KeyException("The alias does not exist or does not identify a key-related entry: " + alias);
        }

        /* KeyStore#getKey throws:
        KeyStoreException – if the keystore has not been initialized (loaded).
        NoSuchAlgorithmException – if the algorithm for recovering the key cannot be found
        UnrecoverableKeyException – if the key cannot be recovered (e.g., the given password is wrong).
         */
        PrivateKey key;
        if (password != null) {
            key = (PrivateKey) keyStore.getKey(alias, password.toCharArray()); // may return null if the given alias does not exist or does not identify a key-related entry
        } else {
            key = (PrivateKey) keyStore.getKey(alias, null); // may return null if the given alias does not exist or does not identify a key-related entry
        }

        if (key == null) {
            throw new KeyException("The alias does not exist or does not identify a key-related entry: " + alias);
        }

        // throws KeyStoreException – if the keystore has not been initialized (loaded)
        var cert = keyStore.getCertificate(alias); // may return null if the given alias does not exist or does not contain a certificate
        if (cert == null) {
            throw new KeyException("The alias does not exist or does not contain a certificate: " + alias);
        }

        var publicKey = cert.getPublicKey();

        // CAUTION In case of Securosys JCE provider for Securosys Primus HSM ("SecurosysPrimusXSeries"), key translation is required
        final KeyFactory keyFactory = KeyFactory.getInstance("EC", keyStore.getProvider());
        // Translate a key object (whose provider may be unknown or potentially untrusted) into a corresponding key object of this key factory
        publicKey = (PublicKey) keyFactory.translateKey(cert.getPublicKey()); // "exported key"

        return new KeyPair(publicKey, key);
    }
}
