import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;

/**
 * This class can be used to parse and hold the data from a SSH-SK attestation document.
 */
public class SshAttestation {
    private byte[] attestationCertificate;
    private byte[] enrollmentSignature;
    private byte[] authenticatorDataCbor;
    private int flags;
    private byte[] reserved;

    public byte[] getAttestationCertificate() {
        return attestationCertificate.clone();
    }

    public byte[] getEnrollmentSignature() {
        return enrollmentSignature.clone();
    }

    public byte[] getAuthenticatorDataCbor() {
        return authenticatorDataCbor.clone();
    }

    public int getFlags() {
        return flags;
    }

    public byte[] getReserved() {
        return reserved.clone();
    }

    public static SshAttestation parse(byte[] raw) {
        Buffer buffer = new ByteArrayBuffer(raw);
        String magic = buffer.getString();
        if (!"ssh-sk-attest-v01".equals(magic)) {
            throw new IllegalArgumentException("Invalid magic header; " + magic);
        }

        SshAttestation attestation = new SshAttestation();
        attestation.attestationCertificate = buffer.getBytes();
        attestation.enrollmentSignature = buffer.getBytes();
        attestation.authenticatorDataCbor = buffer.getBytes();
        attestation.flags = buffer.getInt();
        attestation.reserved = buffer.getBytes();

        if (buffer.available() > 0) {
            throw new IllegalArgumentException("Found trailing data.");
        }

        return attestation;
    }
}
