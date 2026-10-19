package ch.admin.bj.swiyu.didtoolbox.securosys.primus;

import lombok.AccessLevel;
import lombok.Getter;

import java.io.*;
import java.lang.reflect.InvocationTargetException;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Locale;
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
    public static final String PROVIDER_CLASS = "com.securosys.primus.jce.PrimusProvider";
    private static final String KEY_STORE_TYPE_GETTER = "getKeyStoreTypeName";
    private static final String PROVIDER_NAME_GETTER = "getProviderName";
    @Getter(AccessLevel.PUBLIC)
    private final KeyStore keyStore;

    /**
     * The empty constructor.
     * <p>
     * CAUTION This constructor does not make any attempt to load the keystore, as no transport configuration is known at the time.
     * Use other constructors for that purpose.
     *
     * @throws PrimusKeyStoreInitializationException
     */
    public PrimusKeyStoreLoader() throws PrimusKeyStoreInitializationException {
        this.keyStore = initKeyStore();
    }

    protected KeyStore initKeyStore() throws PrimusKeyStoreInitializationException {
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
            return KeyStore.getInstance(type, providerName);

            // CAUTION Needless to say, calling this.keyStore.load(null) at this point would cause:
            //         com.securosys.primus.jce.transport.TransportUnconfiguredException: transport configuration not yet set

        } catch (ClassNotFoundException | NoSuchMethodException | InstantiationException | IllegalAccessException |
                 InvocationTargetException | KeyStoreException | NoSuchProviderException e) {
            throw new PrimusKeyStoreInitializationException(
                    "Failed to initialize Securosys Primus Key Store. Ensure the required lib/primusX-java[8|11].jar libraries exist on the system", e);
        }
    }

    /**
     * The constructor capable of loading credentials from the system environment.
     * The relevant envvars are described by {@link SecurosysPrimusEnvironment}.
     * <p>
     * If supplied, credentials may also be loaded from a file, as fallback to system environment variables.
     * WARNING: the password remains in memory for an indeterminate amount of time.
     *
     * @param credentials a property file featuring all Primus {@code com.securosys.primus.jce.credentials.*}
     *                    required to load the keystore
     * @throws CertificateException
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws PrimusKeyStoreInitializationException
     */
    @SuppressWarnings({"PMD.CognitiveComplexity", "PMD.CyclomaticComplexity"})
    public PrimusKeyStoreLoader(File credentials)
            throws CertificateException, IOException, NoSuchAlgorithmException, PrimusKeyStoreInitializationException {
        this.keyStore = initKeyStore();

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
            throw new PrimusKeyStoreInitializationException("Securosys Primus HSM host cannot be resolved. "
                    + "You may supply it either via property file or by setting the relevant system environment variable: " // NOPMD
                    + SecurosysPrimusEnvironment.SECUROSYS_PRIMUS_HOST.name());
        }

        var portAsString = System.getenv(SecurosysPrimusEnvironment.SECUROSYS_PRIMUS_PORT.name());
        if (portAsString == null && props != null) {
            portAsString = props.getProperty(SecurosysPrimusEnvironment.SECUROSYS_PRIMUS_PORT.toProperty());
        }
        var port = -1; // change to int and add bounds check to also allow ports over ~32'500 since max part is 2^16~=65'000
        try {
            if (portAsString != null) {
                port = Integer.parseInt(portAsString);
            }
            if (port > (2 << 16) -1) { // Max Unix port is max of an unsigned 16bit integer
                throw new PrimusKeyStoreInitializationException("Securosys Primus HSM port is invalid.");
            }
        } catch (NumberFormatException ignored) {
            throw new PrimusKeyStoreInitializationException("Securosys Primus HSM port is invalid.");
        }
        if (port < 0) {
            throw new PrimusKeyStoreInitializationException("Securosys Primus HSM port cannot be resolved. "
                    + "You may supply it either via property file or by setting the relevant system environment variable: "
                    + SecurosysPrimusEnvironment.SECUROSYS_PRIMUS_PORT.name());
        }

        var user = System.getenv(SecurosysPrimusEnvironment.SECUROSYS_PRIMUS_USER.name());
        if (user == null && props != null) {
            user = props.getProperty(SecurosysPrimusEnvironment.SECUROSYS_PRIMUS_USER.toProperty());
        }
        if (user == null) {
            throw new PrimusKeyStoreInitializationException("Securosys Primus HSM user cannot be resolved. "
                    + "You may supply it either via property file or by setting the relevant system environment variable: "
                    + SecurosysPrimusEnvironment.SECUROSYS_PRIMUS_USER.name());
        }

        var password = System.getenv(SecurosysPrimusEnvironment.SECUROSYS_PRIMUS_PASSWORD.name());
        if (password == null && props != null) {
            password = props.getProperty(SecurosysPrimusEnvironment.SECUROSYS_PRIMUS_PASSWORD.toProperty());
        }
        if (password == null) {
            throw new PrimusKeyStoreInitializationException("Securosys Primus HSM password cannot be resolved. "
                    + "You may supply it either via property file or by setting the relevant system environment variable: "
                    + SecurosysPrimusEnvironment.SECUROSYS_PRIMUS_PASSWORD.name());
        }

        // Throws: IOException – if there is an I/O or format problem with the keystore data, if a password is required but not given,
        //                       or if the given password was incorrect. If the error is due to a wrong password,
        //                       the cause of the IOException should be an UnrecoverableKeyException
        //         NoSuchAlgorithmException – if the algorithm used to check the integrity of the keystore cannot be found
        //         CertificateException – if any of the certificates in the keystore could not be loaded
        var param = SecurosysPrimusEnvironment.build(host, port, user, password.toCharArray());
        var stream = new ByteArrayInputStream(param);
        this.keyStore.load(stream, null);
        Arrays.fill(param, (byte) 0); // Wipe sensitive data from array
    }

    /**
     * Initializes a SecuroSys keystore with the provided parameters.
     *
     * @param host
     * @param port
     * @param user
     * @param password, Array will be filled with spaces after usage.
     * @throws CertificateException
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws PrimusKeyStoreInitializationException
     */
    public PrimusKeyStoreLoader(String host,
                                int port,
                                String user,
                                char[] password)
            throws CertificateException, IOException, NoSuchAlgorithmException, PrimusKeyStoreInitializationException {

        this();

        // Throws: IOException – if there is an I/O or format problem with the keystore data, if a password is required but not given,
        //                       or if the given password was incorrect. If the error is due to a wrong password,
        //                       the cause of the IOException should be an UnrecoverableKeyException.
        //         NoSuchAlgorithmException – if the algorithm used to check the integrity of the keystore cannot be found.
        //         CertificateException – if any of the certificates in the keystore could not be loaded.
        var param = SecurosysPrimusEnvironment.build(host, port, user, password);
        var stream = new ByteArrayInputStream(param);
        this.keyStore.load(stream, null);
        Arrays.fill(param, (byte) 0); // Wipe sensitive data from array
    }

    /**
     * The system envvars storing the credentials required to load Securosys Primus Key Store.
     */
    public enum SecurosysPrimusEnvironment {
        SECUROSYS_PRIMUS_HOST, SECUROSYS_PRIMUS_PORT, SECUROSYS_PRIMUS_USER, SECUROSYS_PRIMUS_PASSWORD;

        /**
         * Assembles a (byte) stream suitable for feeding (directly) into Primus' keystore.
         */
        @SuppressWarnings("PMD.RelianceOnDefaultCharset")
        static byte[] build(String host,
                            int port,
                            String user,
                            char[] password) {
            // ad-hoc configuration - assemble a byte stream to feed into Primus' keystore
            final var baos = new ByteArrayOutputStream(1024);
            baos.writeBytes("com.securosys.primus.jce.credentials.host=".getBytes(StandardCharsets.UTF_8));
            baos.writeBytes(host.getBytes(StandardCharsets.UTF_8));
            baos.writeBytes(System.lineSeparator().getBytes(StandardCharsets.UTF_8));
            baos.writeBytes("com.securosys.primus.jce.credentials.port=".getBytes(StandardCharsets.UTF_8));
            baos.writeBytes(Integer.toString(port).getBytes(StandardCharsets.UTF_8));
            baos.writeBytes(System.lineSeparator().getBytes(StandardCharsets.UTF_8));
            baos.writeBytes("com.securosys.primus.jce.credentials.user=".getBytes(StandardCharsets.UTF_8));
            baos.writeBytes(user.getBytes(StandardCharsets.UTF_8));
            baos.writeBytes(System.lineSeparator().getBytes(StandardCharsets.UTF_8));
            baos.writeBytes("com.securosys.primus.jce.credentials.password=".getBytes(StandardCharsets.UTF_8));

            // Convert CharArray to ByteArray via CharBuffer and encode to avoid allocating a string
            var pwArray = Charset.defaultCharset().encode(CharBuffer.wrap(password)).array();
            Arrays.fill(password, ' ');
            var pwArrayWithoutNullByte = Arrays.copyOf(pwArray, pwArray.length-1);
            baos.writeBytes(pwArrayWithoutNullByte);
            // Clean arrays to purge the pw from memory.
            Arrays.fill(pwArrayWithoutNullByte, (byte)0);
            Arrays.fill(pwArray, (byte)0);

            baos.writeBytes(System.lineSeparator().getBytes(StandardCharsets.UTF_8));
            var result = baos.toByteArray();

            // Wipe buffer in baos
            var size = baos.size();
            baos.reset();
            baos.writeBytes(new byte[size]);

            return result;
        }

        private String toProperty() {
            return this.name().toLowerCase(Locale.ROOT);
        }
    }

    /**
     * Loads a key (pair) from the underlying Primus key store. The key is associated with the given {@code alias},
     * using the given {@code password} to recover it.
     *
     * @param alias    the alias name
     * @param password the password for recovering the key
     * @return the requested key, or {@code null} if the given {@code alias} does not exist or does not identify a key-related entry.
     * @throws UnrecoverableEntryException if the key cannot be recovered (e.g., the given password is wrong).
     * @throws KeyStoreException if the keystore has not been initialized (loaded).
     * @throws NoSuchAlgorithmException if the algorithm for recovering the key cannot be found
     * @throws KeyException
     */
    @SuppressWarnings("PMD.UnusedAssignment")
    public KeyPair loadKeyPair(String alias, char[] password)
            throws UnrecoverableEntryException, KeyStoreException, NoSuchAlgorithmException, KeyException {

        var keyStore = this.getKeyStore();

        if (!keyStore.isKeyEntry(alias)) {
            throw new KeyException("The alias does not exist or does not identify a key-related entry: " + alias);
        }

        PrivateKey key;
        if (password != null) {
            key = (PrivateKey) keyStore.getKey(alias, password); // may return null if the given alias does not exist or does not identify a key-related entry
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