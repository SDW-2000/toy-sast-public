package fixtures.remaining.manual;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Arrays;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

final class Safe {
    byte[] copyWithinBounds(byte[] source, int requestedLength) {
        if (requestedLength < 0 || requestedLength > source.length) {
            throw new IllegalArgumentException("invalid length");
        }
        return Arrays.copyOf(source, requestedLength);
    }

    int readBeforeClose(byte[] data) throws IOException {
        ByteArrayInputStream stream = new ByteArrayInputStream(data);
        try {
            return stream.read();
        } finally {
            stream.close();
        }
    }

    HttpSession requestSession(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        return session;
    }
}
