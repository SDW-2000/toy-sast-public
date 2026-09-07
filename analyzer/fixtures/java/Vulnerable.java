import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.net.URL;
import java.net.URLConnection;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.util.Random;
import javax.net.ssl.HttpsURLConnection;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilderFactory;

final class Vulnerable {
    Object evaluate(HttpServletRequest request) throws Exception {
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("JavaScript");
        String code = "(" + request.getParameter("expression") + ")";
        return engine.eval(code);
    }

    Process runCommand(HttpServletRequest request) throws IOException {
        String command = "printf " + request.getParameter("message");
        return Runtime.getRuntime().exec(command);
    }

    void enableExternalEntities(DocumentBuilderFactory factory) throws Exception {
        factory.setFeature("http://xml.org/sax/features/external-general-entities", true);
    }

    URLConnection fetch(HttpServletRequest request) throws IOException {
        String targetUrl = "http://" + request.getParameter("host") + "/health";
        return new URL(targetUrl).openConnection();
    }

    void exposeFile(File report) {
        report.setWritable(true, false);
    }

    void weakCrypto() throws Exception {
        MessageDigest.getInstance("MD5");
    }

    String hardcodedCredential() {
        String databasePassword = "prod-secret-12345";
        return databasePassword;
    }

    void shortKey() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(1536);
    }

    long predictableToken() {
        long sessionToken = new Random().nextLong();
        return sessionToken;
    }

    void trustEveryHostname(HttpsURLConnection connection) {
        connection.setHostnameVerifier((hostname, session) -> true);
    }

    Cookie insecureCookie() {
        Cookie cookie = new Cookie("session", "value");
        cookie.setMaxAge(86400);
        return cookie;
    }

    // api_key = "development-secret!@#$%^&*()"
    String leakedCommentMarker() {
        return "comment above contains a credential";
    }

    byte[] hashPassword(String password) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(password.getBytes());
    }

    void spinForever() {
        while (true) {
            System.out.println("still running");
        }
    }

    void exposeFailure(HttpServletResponse response, Exception exception) throws IOException {
        response.getWriter().write(exception.getMessage());
    }

    void ignoreIoFailure() {
        try {
            throw new IOException("failure");
        } catch (IOException ignored) {
        }
    }

    void catchEverything() {
        try {
            throw new IllegalStateException("failure");
        } catch (Exception exception) {
            System.err.println("operation failed");
        }
    }

    Object deserialize(InputStream input) throws Exception {
        ObjectInputStream stream = new ObjectInputStream(input);
        return stream.readObject();
    }

    void debug(Exception exception) {
        exception.printStackTrace();
    }
}
