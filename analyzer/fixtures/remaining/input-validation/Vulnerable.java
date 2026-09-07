import java.io.File;
import java.nio.file.Path;
import javax.servlet.http.HttpServletRequest;
import javax.xml.xpath.XPath;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.web.multipart.MultipartFile;
import org.w3c.dom.Document;

final class VulnerableInputValidation {
    File readRequestedFile(HttpServletRequest request, File reportRoot) {
        String requestedName = request.getParameter("report");
        return new File(reportRoot, requestedName);
    }

    void storeUpload(MultipartFile upload, Path uploadRoot) throws Exception {
        upload.transferTo(uploadRoot.resolve(upload.getOriginalFilename()));
    }

    String evaluateUserXPath(HttpServletRequest request, XPath xpath, Document document)
            throws Exception {
        String account = request.getParameter("account");
        String expression = "//user[name='" + account + "']/role/text()";
        return xpath.evaluate(expression, document);
    }

    void disableCsrf(HttpSecurity http) throws Exception {
        http.csrf().disable();
    }

    byte[] allocateRequestedBuffer(HttpServletRequest request) {
        return new byte[Integer.parseInt(request.getParameter("count")) * 1_048_576];
    }

    void printUserFormat(HttpServletRequest request, String account) {
        String format = request.getParameter("format");
        System.out.printf(format, account);
    }
}
