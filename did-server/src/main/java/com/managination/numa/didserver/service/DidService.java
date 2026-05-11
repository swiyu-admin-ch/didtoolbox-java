package com.managination.numa.didserver.service;

import ch.admin.eid.did_sidekicks.DidDocExtended;
import ch.admin.eid.didresolver.Did;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.managination.numa.didserver.dto.*;
import com.managination.numa.didserver.model.JsonWebKey;
import jakarta.annotation.PostConstruct;
import lombok.Getter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.lang.management.MemoryUsage;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;

@Service
@Getter
public class DidService {

   private static final Logger log = LoggerFactory.getLogger(DidService.class);

   @Value("${storage.did.path:./storage/dids}")
   private String storagePath = "./storage/dids";

   private KeyPair serverKeyPair;
   private JsonWebKey serverPublicKey;
   private Instant keyRotatedAt;

   @PostConstruct
   public void init() {
      initializeServerKey();
   }

   private void initializeServerKey() {
      String path = storagePath != null ? storagePath : "./storage/dids";
      try {
         Path storageDir = Paths.get(path);
         if (!Files.exists(storageDir)) {
            Files.createDirectories(storageDir);
         }

         Path privateKeyPath = storageDir.resolve("server-key.pem");
         Path publicKeyPath = storageDir.resolve("server-pubkey.pem");

         if (Files.exists(privateKeyPath) && Files.exists(publicKeyPath)) {
            serverKeyPair = loadKeyPair(privateKeyPath, publicKeyPath);
         } else {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
            keyGen.initialize(256);
            serverKeyPair = keyGen.generateKeyPair();
            saveKeyPair(serverKeyPair, privateKeyPath, publicKeyPath);
         }

         ECPublicKey pubKey = (ECPublicKey) serverKeyPair.getPublic();

         byte[] xBytes = pubKey.getW().getAffineX().toByteArray();
         byte[] yBytes = pubKey.getW().getAffineY().toByteArray();

         serverPublicKey = new JsonWebKey(
               "EC",
               "auth-0",
               "P-256",
               Base64.getUrlEncoder().withoutPadding().encodeToString(xBytes),
               Base64.getUrlEncoder().withoutPadding().encodeToString(yBytes)
         );
         keyRotatedAt = Instant.now();
      } catch (Exception e) {
         log.error("Failed to initialize server key pair", e);
         throw new RuntimeException("Failed to initialize server key pair", e);
      }
   }

   private void saveKeyPair(KeyPair keyPair, Path privateKeyPath, Path publicKeyPath) throws IOException {
      String privateKeyPem = "-----BEGIN PRIVATE KEY-----\n" +
            Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(keyPair.getPrivate().getEncoded()) +
            "\n-----END PRIVATE KEY-----\n";

      String publicKeyPem = "-----BEGIN PUBLIC KEY-----\n" +
            Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(keyPair.getPublic().getEncoded()) +
            "\n-----END PUBLIC KEY-----\n";

      Files.writeString(privateKeyPath, privateKeyPem);
      Files.writeString(publicKeyPath, publicKeyPem);
   }

   private KeyPair loadKeyPair(Path privateKeyPath, Path publicKeyPath) throws Exception {
      String privateKeyPem = Files.readString(privateKeyPath, StandardCharsets.UTF_8);
      String publicKeyPem = Files.readString(publicKeyPath, StandardCharsets.UTF_8);

      byte[] privateKeyBytes = Base64.getMimeDecoder().decode(
            privateKeyPem
                  .replace("-----BEGIN PRIVATE KEY-----", "")
                  .replace("-----END PRIVATE KEY-----", "")
                  .replaceAll("\\s", "")
      );

      byte[] publicKeyBytes = Base64.getMimeDecoder().decode(
            publicKeyPem
                  .replace("-----BEGIN PUBLIC KEY-----", "")
                  .replace("-----END PUBLIC KEY-----", "")
                  .replaceAll("\\s", "")
      );

      KeyFactory keyFactory = KeyFactory.getInstance("EC");
      PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
      PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));

      return new KeyPair(publicKey, privateKey);
   }

   public HealthStatus getHealthStatus() {
      FilesystemHealth fsHealth = checkFilesystemHealth();
      MemoryHealth memHealth = checkMemoryHealth();
      JvmHealth jvmHealth = checkJvmHealth();
      EnvironmentHealth envHealth = checkEnvironmentHealth();

      boolean allHealthy = "UP".equals(fsHealth.status())
            && "UP".equals(memHealth.status());

      return new HealthStatus(
            allHealthy ? "UP" : "DEGRADED",
            Instant.now(),
            fsHealth,
            memHealth,
            jvmHealth,
            envHealth
      );
   }

   private FilesystemHealth checkFilesystemHealth() {
      try {
         Path resolvedPath = Paths.get(storagePath);
         if (!Files.exists(resolvedPath)) {
            Files.createDirectories(resolvedPath);
         }

         Path testFile = resolvedPath.resolve(".health-check-temp");
         Files.writeString(testFile, "health-check");
         Files.delete(testFile);

         if (!Files.isReadable(resolvedPath)) {
            return new FilesystemHealth("DOWN", storagePath, null, "Storage path is not readable");
         }

         long usableSpace = Files.getFileStore(resolvedPath).getUsableSpace();
         long minRequiredSpace = 100 * 1024 * 1024;

         if (usableSpace < minRequiredSpace) {
            return new FilesystemHealth("DEGRADED", storagePath, formatBytes(usableSpace), "Low disk space");
         }

         return new FilesystemHealth("UP", storagePath, formatBytes(usableSpace), null);
      } catch (Exception e) {
         return new FilesystemHealth("DOWN", storagePath, null, "Error: " + e.getMessage());
      }
   }

   private MemoryHealth checkMemoryHealth() {
      MemoryMXBean memoryBean = ManagementFactory.getMemoryMXBean();
      MemoryUsage heapUsage = memoryBean.getHeapMemoryUsage();
      MemoryUsage nonHeapUsage = memoryBean.getNonHeapMemoryUsage();

      long heapMax = heapUsage.getMax();
      long heapUsed = heapUsage.getUsed();
      long heapCommitted = heapUsage.getCommitted();
      double heapUsagePercent = (double) heapUsed / heapMax * 100;

      HeapMemory heap = new HeapMemory(
            formatBytes(heapMax),
            formatBytes(heapUsed),
            formatBytes(heapCommitted),
            String.format("%.2f", heapUsagePercent)
      );

      NonHeapMemory nonHeap = new NonHeapMemory(
            formatBytes(nonHeapUsage.getUsed()),
            formatBytes(nonHeapUsage.getCommitted())
      );

      String status;
      if (heapUsagePercent > 90) {
         status = "DOWN";
      } else if (heapUsagePercent > 75) {
         status = "DEGRADED";
      } else {
         status = "UP";
      }

      return new MemoryHealth(status, heap, nonHeap);
   }

   private JvmHealth checkJvmHealth() {
      Runtime runtime = Runtime.getRuntime();
      int threadCount = ManagementFactory.getThreadMXBean().getThreadCount();
      int peakThreadCount = ManagementFactory.getThreadMXBean().getPeakThreadCount();
      long gcCollections = ManagementFactory.getGarbageCollectorMXBeans().stream()
            .mapToLong(bean -> bean.getCollectionCount())
            .sum();

      return new JvmHealth(
            runtime.availableProcessors(),
            threadCount,
            peakThreadCount,
            ManagementFactory.getRuntimeMXBean().getUptime() + "ms",
            ManagementFactory.getRuntimeMXBean().getVmName(),
            ManagementFactory.getRuntimeMXBean().getVmVersion(),
            (int) gcCollections,
            "UP"
      );
   }

   private EnvironmentHealth checkEnvironmentHealth() {
      String tempDirStatus;
      try {
         Path tempDir = Paths.get(System.getProperty("java.io.tmpdir"));
         tempDirStatus = Files.isWritable(tempDir) ? "writable" : "not writable";
      } catch (Exception e) {
         tempDirStatus = "error: " + e.getMessage();
      }

      return new EnvironmentHealth(
            tempDirStatus,
            System.getProperty("user.dir"),
            System.getProperty("file.encoding"),
            java.util.Locale.getDefault().toString(),
            "UP"
      );
   }

   private String formatBytes(long bytes) {
      if (bytes < 0) return "unknown";
      if (bytes < 1024) return bytes + " B";
      int exp = (int) (Math.log(bytes) / Math.log(1024));
      String pre = "KMGTPE".charAt(exp - 1) + "";
      return String.format("%.2f %sB", bytes / Math.pow(1024, exp), pre);
   }

   private final ObjectMapper objectMapper;

   public DidService(ObjectMapper objectMapper) {
      this.objectMapper = objectMapper;
   }

   public DidRegistrationResponse verifyAndSaveDid(String didJsonl) {
      String did = "did:webvh:nodid:nothing";
      try {
         String[] normalizedLog = didJsonl.replaceAll("\\r?\\n\\s*", "").replace("}{", "}\n{").split("\\R");
         String lastEntry = normalizedLog[normalizedLog.length - 1];

         WebVhLogEntry logEntry = objectMapper.readValue(lastEntry, WebVhLogEntry.class);

         if (!logEntry.getParameters().getMethod().equals("did:webvh:1.0")) {
            throw new IllegalArgumentException("Invalid DID format. Must use did:webvh:1.0");
         }

         did = logEntry.getState().getId();
         Path targetPath = getFilePath(did);

         if (Files.exists(targetPath)) {
            String[] storedJsonl = resolveDid(did).split("\\R");
            WebVhLogEntry storedLogEntry = objectMapper.readValue(storedJsonl[storedJsonl.length - 1], WebVhLogEntry.class);
            String storedDid = storedLogEntry.getState().getId();
            if(!storedDid.equals(did)) {
               throw new IllegalStateException("Stored DID " + storedDid + " does not match provided did: " + did);
            }
         }

         String normalizedLogString = String.join(System.lineSeparator(), normalizedLog);
         DidDocExtended didDoc = new Did(did).resolveAll(normalizedLogString);
         saveFile(targetPath, normalizedLogString);

         return new DidRegistrationResponse(true, did, "DID registered successfully");
      } catch (Exception e) {
         log.error("Failed to register DID: {}", did, e);
         throw new RuntimeException("DID registration failed: " + e.getMessage(), e);
      }
   }

   public String resolveDid(String did) throws IOException {
      if (!did.startsWith("did:webvh:")) {
         throw new IllegalArgumentException("Invalid DID format. Must start with did:webvh:");
      }

      Path targetPath = getFilePath(did);
      if (!Files.exists(targetPath)) {
         throw new DidNotFoundException("DID not found: " + did);
      }

      return Files.readString(targetPath, StandardCharsets.UTF_8);
   }

   public ServerPublicKeyResponse getServerPublicKey() {
      return new ServerPublicKeyResponse(
            serverPublicKey,
            "server-key-1",
            "ES256",
            keyRotatedAt
      );
   }

   private String extractDomainFromDid(String didId) {
      String[] parts = didId.split(":");
      if (parts.length < 4 || !parts[0].equals("did") || !parts[1].equals("webvh")) {
         throw new IllegalArgumentException("Only did:webvh with SCID is supported currently");
      }
      return parts[3];
   }

   private Path getFilePath(String didId) {
      String[] parts = didId.split(":");
      // use extractDomainFromDid so that an error is thrown if the DID method is not webvh
      String domain = extractDomainFromDid(didId);
      Path fullPath = Paths.get(storagePath).resolve(domain);

      if (parts.length == 4) {
         fullPath = fullPath.resolve(".well-known");
      } else {
         for (int i = 4; i < parts.length; i++) {
            fullPath = fullPath.resolve(parts[i]);
         }
      }

      return fullPath.resolve("did.jsonl");
   }

   private void saveFile(Path targetPath, String content) throws IOException {
      Path parentDir = targetPath.getParent();
      if (!Files.exists(parentDir)) {
         Files.createDirectories(parentDir);
      }
      Files.writeString(targetPath, content);
   }

   public static class DidNotFoundException extends RuntimeException {
      public DidNotFoundException(String message) {
         super(message);
      }
   }

   @Getter
   public static class VersionConflictException extends RuntimeException {
      private final String serverVersionId;
      private final String clientVersionId;
      private final WebVhDidDocument serverDocument;

      public VersionConflictException(String message, String serverVersionId, String clientVersionId, WebVhDidDocument serverDocument) {
         super(message);
         this.serverVersionId = serverVersionId;
         this.clientVersionId = clientVersionId;
         this.serverDocument = serverDocument;
      }

   }
}
