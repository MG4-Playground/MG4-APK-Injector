import javax.net.ssl.*;
import java.io.*;
import java.net.InetSocketAddress;
import java.nio.file.*;
import java.security.KeyStore;
import java.security.cert.*;
import java.util.*;

/**
 * JSSE TLS 客户端: 用指定根证书作为唯一信任锚, 连接指定 host:port。
 * 模拟 Android 车机 (Conscrypt/JSSE) 的系统 CA 库校验行为。
 *
 * 用法: java JsseTlsClient <host> <port> <sni> <rootPem>
 * 退出码 0 = 握手成功
 */
public class JsseTlsClient {

    public static void main(String[] args) throws Exception {
        String host = args[0];
        int port = Integer.parseInt(args[1]);
        String sni = args[2];
        String rootPem = args[3];

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(null, null);
        int i = 0;
        for (X509Certificate c : loadAll(cf, rootPem)) {
            ks.setCertificateEntry("r" + (i++), c);
        }
        TrustManagerFactory tmf =
                TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ks);

        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, tmf.getTrustManagers(), null);

        // 用 SSLSocketFactory 直接建带 SNI 的连接
        SSLSocketFactory sf = ctx.getSocketFactory();
        SSLSocket sock = (SSLSocket) sf.createSocket();
        sock.connect(new InetSocketAddress(host, port), 10000);
        sock.setSoTimeout(10000);

        // 设置 SNI 与主机名校验目标
        SSLParameters p = sock.getSSLParameters();
        p.setServerNames(Collections.singletonList(new SNIHostName(sni)));
        p.setEndpointIdentificationAlgorithm("HTTPS");
        sock.setSSLParameters(p);

        sock.startHandshake();

        System.out.println("OK " + sock.getSession().getPeerCertificates().length);
        sock.close();
        System.exit(0);
    }

    static List<X509Certificate> loadAll(CertificateFactory cf, String p) throws Exception {
        List<X509Certificate> out = new ArrayList<>();
        String pem = new String(Files.readAllBytes(Paths.get(p)), "UTF-8");
        for (String part : pem.split("-----BEGIN CERTIFICATE-----")) {
            if (!part.contains("-----END CERTIFICATE-----")) continue;
            String body = part.substring(0, part.indexOf("-----END CERTIFICATE-----"));
            byte[] der = Base64.getMimeDecoder().decode(body);
            out.add((X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der)));
        }
        return out;
    }
}
