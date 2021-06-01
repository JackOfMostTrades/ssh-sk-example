import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * This is a simple POJO that is used as an intermediate object when converting from an SSH attestation statement to
 * a webauthn attestation object.
 */
public class RawAttestationObject {
    private String format;
    private byte[] authenticatorData;
    private PackedAttestationStatement attestationStatement;

    @JsonProperty("authData")
    public byte[] getAuthenticatorData() {
        return authenticatorData;
    }

    public void setAuthenticatorData(byte[] authenticatorData) {
        this.authenticatorData = authenticatorData;
    }

    @JsonProperty("attStmt")
    public PackedAttestationStatement getAttestationStatement() {
        return attestationStatement;
    }

    public void setAttestationStatement(PackedAttestationStatement attestationStatement) {
        this.attestationStatement = attestationStatement;
    }

    @JsonProperty("fmt")
    public String getFormat() {
        return format;
    }

    public void setFormat(String format) {
        this.format = format;
    }

    public static class PackedAttestationStatement {
        private long alg;
        private byte[] sig;
        private byte[][] x5c;

        public PackedAttestationStatement(long alg, byte[] sig, byte[][] x5c) {
            this.alg = alg;
            this.sig = sig;
            this.x5c = x5c;
        }

        @JsonProperty("alg")
        public long getAlg() {
            return alg;
        }

        @JsonProperty("sig")
        public byte[] getSig() {
            return sig;
        }

        @JsonProperty("x5c")
        public byte[][] getX5c() {
            return x5c;
        }
    }
}
