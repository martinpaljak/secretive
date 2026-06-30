import Foundation
import Testing
import SSHProtocolKit

@Suite struct SignedDataContextTests {

    // SSH user authentication blob, RFC 4252 section 7:
    // string session-id, byte 50, string user, string service, string "publickey", bool, string alg, string key.
    @Test func userAuthentication() {
        var blob = Data()
        blob.append("session-id".wire)
        blob.append(50)
        blob.append("martin".wire)
        blob.append("ssh-connection".wire)
        blob.append("publickey".wire)
        blob.append(1)
        blob.append("ssh-ed25519".wire)
        blob.append("key-blob".wire)
        let context = SignedDataContext(parsing: blob)
        #expect(context == .userAuthentication(user: "martin"))
        #expect(context.localizedPurpose?.contains("martin") == true)
    }

    // SSHSIG blob, PROTOCOL.sshsig: magic "SSHSIG", string namespace, string reserved, string hash-alg, string hash.
    @Test func sshsig() {
        var blob = Data("SSHSIG".utf8)
        blob.append("git".wire)
        blob.append(Data().wire)
        blob.append("sha512".wire)
        blob.append(Data(repeating: 0xAB, count: 64).wire)
        let context = SignedDataContext(parsing: blob)
        #expect(context == .sshsig(namespace: "git"))
        #expect(context.localizedPurpose?.contains("git") == true)
    }

    // Certificate TBS, PROTOCOL.certkeys: string type, string nonce, <pubkey fields>, uint64 serial,
    // uint32 type, string key id, ... For ed25519 the only public key field is the 32-byte pk.
    @Test func certificate() {
        var blob = Data()
        blob.append("ssh-ed25519-cert-v01@openssh.com".wire)
        blob.append(Data(repeating: 0x11, count: 32).wire)                  // nonce
        blob.append(Data(repeating: 0x22, count: 32).wire)                  // pk
        blob.append(Data([0, 0, 0, 0, 0, 0, 0, 1]))                        // serial
        blob.append(Data([0, 0, 0, 1]))                                    // type: user certificate
        blob.append("admin@example.com".wire)                              // key id
        let context = SignedDataContext(parsing: blob)
        #expect(context == .certificate(keyID: "admin@example.com"))
        #expect(context.localizedPurpose?.contains("admin@example.com") == true)
    }

    // An unrecognized certificate algorithm is still reported as a certificate, without a key id.
    @Test func certificateUnknownAlgorithm() {
        var blob = Data()
        blob.append("ssh-future-cert-v01@openssh.com".wire)
        blob.append(Data(repeating: 0x11, count: 32).wire)
        let context = SignedDataContext(parsing: blob)
        #expect(context == .certificate(keyID: nil))
        #expect(context.localizedPurpose != nil)
    }

    @Test func unrecognizedFallsBackToUnknown() {
        #expect(SignedDataContext(parsing: Data()) == .unknown)
        #expect(SignedDataContext(parsing: Data([0x00, 0x01, 0x02, 0x03])) == .unknown)
        // A truncated authentication blob (session id present, code missing) must not misclassify.
        #expect(SignedDataContext(parsing: "session-id".wire) == .unknown)
        #expect(SignedDataContext(parsing: Data()).localizedPurpose == nil)
    }

    // Identifiers shown in the security prompt come from untrusted signed data, so control
    // characters and line breaks must be stripped and the length bounded.
    @Test func displayedIdentifierIsSanitized() {
        var injected = Data()
        injected.append("session-id".wire)
        injected.append(50)
        injected.append("ev\u{0}il\nname\u{200B}".wire)
        injected.append("ssh-connection".wire)
        #expect(SignedDataContext(parsing: injected) == .userAuthentication(user: "evilname"))

        var long = Data()
        long.append("session-id".wire)
        long.append(50)
        long.append(String(repeating: "a", count: 200).wire)
        long.append("ssh-connection".wire)
        guard case .userAuthentication(let user) = SignedDataContext(parsing: long) else {
            Issue.record("expected user authentication")
            return
        }
        #expect(user.count == 64)
        #expect(user.hasSuffix("…"))
    }

    @Test func codableRoundTrip() throws {
        for context: SignedDataContext in [.userAuthentication(user: "martin"), .sshsig(namespace: "git"), .certificate(keyID: "ca"), .certificate(keyID: nil), .unknown] {
            let restored = try JSONDecoder().decode(SignedDataContext.self, from: JSONEncoder().encode(context))
            #expect(restored == context)
        }
    }

}

private extension String {
    /// OpenSSH length-prefixed wire encoding of the string.
    var wire: Data { Data(utf8).wire }
}

private extension Data {
    /// OpenSSH length-prefixed wire encoding of the data.
    var wire: Data {
        var length = UInt32(count).bigEndian
        return unsafe Data(bytes: &length, count: 4) + self
    }
}
