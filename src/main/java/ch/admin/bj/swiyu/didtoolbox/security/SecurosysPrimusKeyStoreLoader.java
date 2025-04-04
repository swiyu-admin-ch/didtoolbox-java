package ch.admin.bj.swiyu.didtoolbox.security;

import lombok.Getter;

import java.io.*;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
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
public class SecurosysPrimusKeyStoreLoader {

    final public static String PROVIDER_CLASS = "com.securosys.primus.jce.PrimusProvider";
    final private static String KEY_STORE_TYPE_GETTER = "getKeyStoreTypeName";
    @Getter
    final private KeyStore keyStore;

    /**
     * The empty constructor.
     * <p>
     * CAUTION This constructor does not make any attempt to load the keystore, as no transport configuration is known at the time.
     * Use other constructors for the purpose.
     *
     * @throws SecurosysPrimusKeyStoreInitializationException
     */
    public SecurosysPrimusKeyStoreLoader() throws SecurosysPrimusKeyStoreInitializationException {
        try {
            // Add Securosys JCE provider for Securosys Primus HSM ("SecurosysPrimusXSeries") via reflection
            var cls = Class.forName(PROVIDER_CLASS);
            var primusProvider = (Provider) cls.getDeclaredConstructor().newInstance();

            Security.addProvider(primusProvider);

            // This JCE provider also able to deliver the correct type that should be used to instantiate java.security.KeyStore object
            // (encapsulating the KeyStoreSpi implementation)
            var type = (String) cls.getDeclaredMethod(KEY_STORE_TYPE_GETTER).invoke(primusProvider);

            // Throws: KeyStoreException – if no provider supports a KeyStoreSpi implementation for the specified type
            //                             (it is the same as checking primusProvider.getService("KeyStore", KEY_STORE_TYPE) against null)
            //         NullPointerException – if type is null
            this.keyStore = KeyStore.getInstance(type);

            // CAUTION Needless to say, calling this.keyStore.load(null) at this point would cause:
            //         com.securosys.primus.jce.transport.TransportUnconfiguredException: transport configuration not yet set

        } catch (Exception e) {
            throw new SecurosysPrimusKeyStoreInitializationException(
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
     * @throws SecurosysPrimusKeyStoreInitializationException
     */
    public SecurosysPrimusKeyStoreLoader(File credentials)
            throws CertificateException, IOException, NoSuchAlgorithmException, SecurosysPrimusKeyStoreInitializationException {

        this();

        Properties props = null;
        if (credentials != null) {
            props = new Properties();
            props.load(new FileInputStream(credentials));
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

    public SecurosysPrimusKeyStoreLoader(String host,
                                         int port,
                                         String user,
                                         String password)
            throws CertificateException, IOException, NoSuchAlgorithmException, SecurosysPrimusKeyStoreInitializationException {

        this();

        // Throws: IOException – if there is an I/O or format problem with the keystore data, if a password is required but not given,
        //                       or if the given password was incorrect. If the error is due to a wrong password,
        //                       the cause of the IOException should be an UnrecoverableKeyException
        //         NoSuchAlgorithmException – if the algorithm used to check the integrity of the keystore cannot be found
        //         CertificateException – if any of the certificates in the keystore could not be loaded
        this.keyStore.load(SecurosysPrimusEnvironment.toStream(host, port, user, password), null);
    }

    public static boolean isPrimusProvider(Provider provider) {
        return provider.getClass().getName().equals(PROVIDER_CLASS);
    }

    /**
     * The system envvars storing the credentials required to load Securosys Primus Key Store.
     */
    enum SecurosysPrimusEnvironment {
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
}
