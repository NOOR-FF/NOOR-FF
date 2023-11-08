private static byte[] getBytesFromInputStream(InputStream is) throws IOException {
    ByteArrayOutputStream os = new ByteArrayOutputStream();
    byte[] buffer = new byte[0xFFFF];
    for (int len = is.read(buffer); len != -1; len = is.read(buffer)) {
        os.write(buffer, 0, len);
    }
    return os.toByteArray();
}

// build a key store from a set of raw certificates
private static KeyStore createKeyStore(Resources resources, int certsId, boolean ca) {
    KeyStore ks = null;
    try {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        if (ca) {
            ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(null, null);
            InputStream certIS = resources.openRawResource(R.raw.ca_crt);
            X509Certificate cert = (X509Certificate) cf.generateCertificate(certIS);
            ks.setCertificateEntry("ca", cert);
        } else {
            ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null, null);
            InputStream certIS = resources.openRawResource(R.raw.client_crt);
            Certificate cert = cf.generateCertificate(certIS);
            InputStream privateKeyIS = resources.openRawResource(R.raw.client_pkcs8);
            byte[] privateKeyBytes = RNGrpcChannelBuilder.getBytesFromInputStream(privateKeyIS);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
            Certificate[] certChain = new Certificate[1];
            certChain[0] = cert;
            ks.setKeyEntry("client", privateKey, null, certChain);
        }
    } catch (Exception e) {
        throw new RuntimeException(e);
    }
    return ks;
}

public static ManagedChannel build(String host, int port, Resources resources,
    @Nullable String serverHostOverride) {
    KeyStore ca = RNGrpcChannelBuilder.createKeyStore(resources, R.array.certs, true);
    KeyStore client = RNGrpcChannelBuilder.createKeyStore(resources, R.array.certs, false);
    OkHttpChannelBuilder channelBuilder =
        OkHttpChannelBuilder.forAddress(host, port);
    if (serverHostOverride != null) {
        // Force the hostname to match the cert the server uses.
        channelBuilder.overrideAuthority(serverHostOverride);
    }
    try {
        channelBuilder.negotiationType(io.grpc.okhttp.NegotiationType.TLS);
        channelBuilder.useTransportSecurity();
        channelBuilder.sslSocketFactory(getSslSocketFactory(ca, client));
    } catch (Exception e) {
        throw new RuntimeException(e);
    }
    return channelBuilder.build();
}

private static SSLSocketFactory getSslSocketFactory(KeyStore ca, KeyStore client)
throws Exception {
    KeyManagerFactory kmf =
        KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    String password = "";
    kmf.init(client, password.toCharArray());

    // initialize trust manager factor from certs keystore
    TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    tmf.init(ca);

    // initialize SSL context from trust manager factory
    SSLContext context = SSLContext.getInstance("TLS");
    context.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());

    // return socket factory from the SSL context
    return context.getSocketFactory();
}
