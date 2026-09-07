package fixtures.remaining.manual;

import java.io.IOException;
import java.io.InputStream;
import javax.servlet.http.HttpSession;

final class Vulnerable {
    private static HttpSession sharedSession;

    public native void copyToNative(byte[] source);

    int readAfterClose(InputStream stream) throws IOException {
        stream.close();
        return stream.read();
    }
}
