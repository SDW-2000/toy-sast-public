import java.io.File;
import java.net.InetAddress;

final class ToctouExample {
    boolean deleteIfPresent(File target) {
        if (target.exists()) {
            return target.delete();
        }
        return false;
    }
}

final class NullExample {
    void useNull() {
        String label = null;
        label.length();
    }
}

final class PrivateArrayReturnExample {
    private byte[] values = new byte[0];

    public byte[] values() {
        return values;
    }
}

final class PublicArrayAssignmentExample {
    private byte[] values = new byte[0];

    public void setValues(byte[] input) {
        this.values = input;
    }
}

final class DnsDecisionExample {
    boolean isTrustedClient(InetAddress client) {
        return client.getHostName().endsWith(".trusted.example");
    }
}

final class DangerousApiExample {
    void terminate(Thread worker) {
        worker.stop();
    }
}
