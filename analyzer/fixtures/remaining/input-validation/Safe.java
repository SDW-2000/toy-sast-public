import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;
import javax.servlet.http.HttpServletRequest;
import javax.xml.xpath.XPath;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.multipart.MultipartFile;
import org.w3c.dom.Document;

final class SafeInputValidation {
    String readRequestedFile(HttpServletRequest request, Path reportRoot) throws IOException {
        String requestedName = request.getParameter("report");
        if (!requestedName.matches("[A-Za-z0-9._-]+")) {
            throw new IllegalArgumentException("invalid report name");
        }
        Path normalizedRoot = reportRoot.toAbsolutePath().normalize();
        Path target = normalizedRoot.resolve(requestedName).normalize();
        if (!target.startsWith(normalizedRoot)) {
            throw new IllegalArgumentException("report escapes root");
        }
        return Files.readString(target);
    }

    Path storePng(MultipartFile upload, Path uploadRoot) throws IOException {
        byte[] content = upload.getBytes();
        if (content.length < 8
                || content[0] != (byte) 0x89
                || content[1] != 0x50
                || content[2] != 0x4E
                || content[3] != 0x47) {
            throw new IllegalArgumentException("PNG content required");
        }
        String serverGeneratedName = UUID.randomUUID() + ".png";
        Path target = uploadRoot.resolve(serverGeneratedName);
        upload.transferTo(target);
        return target;
    }

    boolean userHasRole(HttpServletRequest request, XPath xpath, Document document)
            throws Exception {
        String expectedAccount = request.getParameter("account");
        String storedAccount = xpath.evaluate("string(//user/name)", document);
        return storedAccount.equals(expectedAccount);
    }

    void configureCsrf(HttpSecurity http) throws Exception {
        http.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
    }

    byte[] allocateBoundedBuffer(HttpServletRequest request) {
        int requestedCount = boundedCount(request.getParameter("count"));
        int byteCount = Math.multiplyExact(requestedCount, 1_048_576);
        return new byte[byteCount];
    }

    private int boundedCount(String rawCount) {
        int parsed = Integer.parseInt(rawCount);
        if (parsed < 1 || parsed > 64) {
            throw new IllegalArgumentException("count out of range");
        }
        return parsed;
    }

    void printUserValue(HttpServletRequest request) {
        String userValue = request.getParameter("format");
        System.out.printf("%s%n", userValue);
    }
}
