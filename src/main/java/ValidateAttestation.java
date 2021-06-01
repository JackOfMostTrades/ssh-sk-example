import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.anchor.SimpleTrustAnchorsProvider;
import com.webauthn4j.anchor.TrustAnchorsResolverImpl;
import com.webauthn4j.data.RegistrationData;
import com.webauthn4j.data.RegistrationParameters;
import com.webauthn4j.data.RegistrationRequest;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.validator.attestation.statement.packed.PackedAttestationStatementValidator;
import com.webauthn4j.validator.attestation.trustworthiness.certpath.TrustAnchorCertPathTrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.self.DefaultSelfAttestationTrustworthinessValidator;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.config.keys.u2f.SkEcdsaPublicKey;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.buffer.keys.SkECBufferPublicKeyParser;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.util.Base64;
import java.util.Collections;

public class ValidateAttestation {

    private static final String APPLICATION_NAME = "ssh://foo";
    private static final String RANDOM_CHALLENGE = "2kmJ3o2Ry9QMrY0mjpoJKqZYU5jYsBv4SDqFTkbiOrQ";

    private final WebAuthnManager webAuthnManager;
    private final ObjectMapper cborMapper;

    private ValidateAttestation() {
        DefaultSelfAttestationTrustworthinessValidator selfAttestationTrustworthinessValidator = new DefaultSelfAttestationTrustworthinessValidator();
        selfAttestationTrustworthinessValidator.setSelfAttestationAllowed(false);
        webAuthnManager = new WebAuthnManager(
                Collections.singletonList(new PackedAttestationStatementValidator()),
                new TrustAnchorCertPathTrustworthinessValidator(new TrustAnchorsResolverImpl(
                        new SimpleTrustAnchorsProvider(Fido2Truststore.getTrustAnchors()))),
                selfAttestationTrustworthinessValidator);
        cborMapper = new ObjectMapper(new CBORFactory());
    }

    public static void main(String[] args) throws Exception {
        ValidateAttestation validateAttestation = new ValidateAttestation();

        final byte[] challengeBytes = Base64.getDecoder().decode(RANDOM_CHALLENGE);
        final byte[] sshAttestationData = Files.readAllBytes(Paths.get("mykey.attestation"));
        validateAttestation.validateAttestationTrusted(challengeBytes, sshAttestationData);

        final byte[] sshPublicKey = Files.readAllBytes(Paths.get("mykey.pub"));
        validateAttestation.validateAttestationMatchesPubkey(sshAttestationData, sshPublicKey);
    }

    private void validateAttestationTrusted(byte[] challengeBytes, byte[] sshAttestationData) throws IOException {
        final byte[] clientDataJson = String.format("{\"type\":\"webauthn.create\",\"challenge\":\"%s\",\"origin\":\"%s\"}",
                Base64.getUrlEncoder().withoutPadding().encodeToString(challengeBytes), APPLICATION_NAME).getBytes(StandardCharsets.UTF_8);

        // Build a webauthn attestation object from the SSH attestation data so that we can verify it with a webauthn library
        byte[] webauthnAttestationObject = buildWebauthnAttestationObject(sshAttestationData);

        RegistrationData registrationData = webAuthnManager.parse(new RegistrationRequest(webauthnAttestationObject, clientDataJson));
        ServerProperty serverProperty = new ServerProperty(
                Origin.create(APPLICATION_NAME),
                APPLICATION_NAME,
                new DefaultChallenge(challengeBytes), null);
        RegistrationParameters registrationParameters = new RegistrationParameters(serverProperty, false, true);
        webAuthnManager.validate(registrationData, registrationParameters);
    }

    private void validateAttestationMatchesPubkey(byte[] sshAttestationData, byte[] sshPublicKeyBytes) throws GeneralSecurityException, IOException {
        // Build a webauthn attestation object from the SSH attestation data so that we can pass it to a webauthn library
        // and get the attested public key back out of the object.
        byte[] webauthnAttestationObject = buildWebauthnAttestationObject(sshAttestationData);
        RegistrationData registrationData = webAuthnManager.parse(new RegistrationRequest(webauthnAttestationObject, null));
        AttestedCredentialData attestedCredentialData = registrationData.getAttestationObject().getAuthenticatorData().getAttestedCredentialData();
        PublicKey attestedPublicKey = attestedCredentialData.getCOSEKey().getPublicKey();

        // Parse the SSH public key with the mina SSHD library
        String[] sshKeyParts = new String(sshPublicKeyBytes, StandardCharsets.UTF_8).split(" ", 3);
        if (!"sk-ecdsa-sha2-nistp256@openssh.com".equals(sshKeyParts[0])) {
            throw new IllegalArgumentException("Unexpected SSH key type: " + sshKeyParts[0]);
        }
        ByteArrayBuffer sshKeyBuffer = new ByteArrayBuffer(Base64.getDecoder().decode(sshKeyParts[1]));
        String keyType = sshKeyBuffer.getString();
        if (!keyType.equals(sshKeyParts[0])) {
            throw new IllegalArgumentException("Unexpected SSH key type: " + keyType);
        }
        SkEcdsaPublicKey sshPublicKey = SkECBufferPublicKeyParser.INSTANCE.getRawPublicKey(keyType, sshKeyBuffer);

        // Verify that the parsed SSH public key matches our expected application name and the attested public key
        if (!sshPublicKey.getAppName().equals(APPLICATION_NAME)) {
            throw new IllegalArgumentException("SSH public key origin does not match attested origin: " + sshPublicKey.getAppName());
        }
        if (!KeyUtils.compareECKeys(sshPublicKey.getDelegatePublicKey(), (ECPublicKey) attestedPublicKey)) {
            throw new IllegalArgumentException("SSH EC public key does not match attested EC public key.");
        }
    }

    private byte[] buildWebauthnAttestationObject(byte[] sshAttestationObject) throws IOException {
        SshAttestation sshAttestation = SshAttestation.parse(sshAttestationObject);
        // Unwrap the CBOR-encoded authenticator data from the attestation
        byte[] authenticatorData = cborMapper.readValue(sshAttestation.getAuthenticatorDataCbor(), byte[].class);

        // Build a "packed" attestation object from the raw SSH parameters.
        RawAttestationObject rawAttestationObject = new RawAttestationObject();
        rawAttestationObject.setFormat("packed");
        rawAttestationObject.setAuthenticatorData(authenticatorData);
        rawAttestationObject.setAttestationStatement(
                new RawAttestationObject.PackedAttestationStatement(
                        COSEAlgorithmIdentifier.ES256.getValue(),
                        sshAttestation.getEnrollmentSignature(),
                        new byte[][]{sshAttestation.getAttestationCertificate()}));
        return cborMapper.writeValueAsBytes(rawAttestationObject);
    }
}
