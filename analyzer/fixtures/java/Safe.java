import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.net.URLConnection;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import javax.net.ssl.HttpsURLConnection;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilderFactory;

final class Safe {
    Object evaluateFixedCode() throws Exception {
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("JavaScript");
        String trustedCode = "40 + 2";
        return engine.eval(trustedCode);
    }

    Process runFixedCommand() throws IOException {
        String trustedCommand = "printf '%s' hello";
        return Runtime.getRuntime().exec(trustedCommand);
    }

    void disableExternalEntities(DocumentBuilderFactory factory) throws Exception {
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
    }

    URLConnection fetchAllowlistedService() throws IOException {
        String trustedUrl = "https://api.example.invalid/health";
        return new URL(trustedUrl).openConnection();
    }

    void protectFile(File report) {
        report.setWritable(true, true);
    }

    String configuredCredential() {
        return System.getenv("DATABASE_PASSWORD");
    }

    void strongKey() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(3072);
    }

    byte[] secureToken() {
        byte[] sessionToken = new byte[32];
        new SecureRandom().nextBytes(sessionToken);
        return sessionToken;
    }

    void verifyHostnames(HttpsURLConnection connection) {
        connection.setHostnameVerifier(HttpsURLConnection.getDefaultHostnameVerifier());
    }

    Cookie secureCookie() {
        Cookie cookie = new Cookie("session", "value");
        cookie.setSecure(true);
        cookie.setMaxAge(-1);
        return cookie;
    }

    void loopWithBreak() {
        while (true) {
            break;
        }
    }

    void loopWithReturn() {
        while (true) {
            return;
        }
    }

    void boundedWork() {
        for (int attempt = 0; attempt < 3; attempt++) {
            System.out.println(attempt);
        }
    }

    void genericFailure(HttpServletResponse response) throws IOException {
        response.getWriter().write("request failed");
    }

    void handleExpectedFailure() {
        try {
            throw new IOException("failure");
        } catch (IOException exception) {
            System.err.println("I/O operation failed");
        }
    }

    String parseJson(String input) {
        return input;
    }

    void logForOperations() {
        System.err.println("operation completed");
    }
}
