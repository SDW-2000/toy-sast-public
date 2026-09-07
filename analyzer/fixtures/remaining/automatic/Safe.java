import java.io.IOException;
import java.net.InetAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

final class AtomicFileExample {
    boolean delete(Path target) throws IOException {
        return Files.deleteIfExists(target);
    }
}

final class NullGuardExample {
    int length(String label) {
        if (label == null) {
            return 0;
        }
        return label.length();
    }
}

final class DefensiveReturnExample {
    private byte[] values = new byte[0];

    public byte[] values() {
        return values.clone();
    }
}

final class DefensiveAssignmentExample {
    private byte[] values = new byte[0];

    public void setValues(byte[] input) {
        this.values = input.clone();
    }
}

final class AddressDecisionExample {
    private static final byte[] TRUSTED_ADDRESS = {127, 0, 0, 1};

    boolean isTrustedClient(InetAddress client) {
        return Arrays.equals(client.getAddress(), TRUSTED_ADDRESS);
    }
}

final class CooperativeTerminationExample {
    void terminate(Thread worker) {
        worker.interrupt();
    }
}
