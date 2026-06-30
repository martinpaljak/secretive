import Foundation

/// Classification of an SSH "data to be signed" blob, describing what a signature authorizes.
///
/// The cases a Secretive key encounters are interactive authentication, detached signatures
/// (git commits, `ssh-keygen -Y sign`), and acting as a CA that signs a certificate. Anything
/// else is reported as `unknown` so the approval prompt keeps its generic wording.
public enum SignedDataContext: Sendable, Codable, Equatable {

    /// SSH user authentication, proving key ownership to log in as `user` (RFC 4252).
    case userAuthentication(user: String)
    /// A detached SSHSIG signature (PROTOCOL.sshsig) over data in `namespace`, such as "git" or "file".
    case sshsig(namespace: String)
    /// A certificate being signed by this key acting as a CA (PROTOCOL.certkeys). `keyID` is the
    /// certificate identity when it could be recovered, nil when the key algorithm is unrecognized.
    case certificate(keyID: String?)
    /// Unrecognized data; the prompt falls back to a generic description.
    case unknown

    /// Classifies a to-be-signed blob. Never throws: unrecognized input yields `.unknown`.
    public init(parsing dataToSign: Data) {
        self = Self.sshsig(from: dataToSign)
            ?? Self.certificate(from: dataToSign)
            ?? Self.userAuthentication(from: dataToSign)
            ?? .unknown
    }

}

extension SignedDataContext {

    /// SSHSIG armored signatures sign a blob prefixed with this magic (PROTOCOL.sshsig).
    private static let sshsigMagic = Data("SSHSIG".utf8)

    /// SSH_MSG_USERAUTH_REQUEST message code, the second field of an authentication blob (RFC 4252, section 7).
    private static let userAuthRequestCode: UInt8 = 50

    /// OpenSSH certificate type names all end with this suffix (PROTOCOL.certkeys).
    private static let certificateTypeSuffix = "-cert-v01@openssh.com"

    /// Upper bound on how much of an attacker-influenced identifier is shown in the approval prompt.
    private static let maxDisplayLength = 64

    /// Reduces an identifier taken from untrusted signed data to something safe to show in the
    /// approval prompt: printable characters only (control, format, and line-break characters
    /// removed, defeating layout spoofing) and a bounded length. Returns nil when nothing
    /// printable remains.
    private static func normalize(_ raw: String) -> String? {
        let disallowed = CharacterSet.controlCharacters
            .union(.illegalCharacters)
            .union(.newlines)
        let printable = String(String.UnicodeScalarView(raw.unicodeScalars.filter { !disallowed.contains($0) }))
        guard !printable.isEmpty else { return nil }
        guard printable.count > maxDisplayLength else { return printable }
        return printable.prefix(maxDisplayLength - 1) + "…"
    }

    private static func sshsig(from data: Data) -> SignedDataContext? {
        guard data.starts(with: sshsigMagic) else { return nil }
        let reader = OpenSSHReader(data: Data(data.dropFirst(sshsigMagic.count)))
        guard let raw = try? reader.readNextChunkAsString(), let namespace = normalize(raw) else { return nil }
        return .sshsig(namespace: namespace)
    }

    private static func certificate(from data: Data) -> SignedDataContext? {
        let reader = OpenSSHReader(data: data)
        guard let type = try? reader.readNextChunkAsString(), type.hasSuffix(certificateTypeSuffix) else { return nil }
        return .certificate(keyID: certificateKeyID(from: reader, type: type))
    }

    private static func userAuthentication(from data: Data) -> SignedDataContext? {
        let reader = OpenSSHReader(data: data)
        guard (try? reader.readNextChunk()) != nil,                              // session identifier
              let code = try? reader.readNextBytes(as: UInt8.self), code == userAuthRequestCode,
              let raw = try? reader.readNextChunkAsString(), let user = normalize(raw) else { return nil }
        return .userAuthentication(user: user)
    }

    /// Recovers a certificate's identity by stepping over the algorithm-specific public key fields
    /// that precede it. Returns nil for unrecognized algorithms or malformed data.
    private static func certificateKeyID(from reader: OpenSSHReader, type: String) -> String? {
        guard let publicKeyChunks = publicKeyChunkCount(forCertificateType: type) else { return nil }
        do {
            _ = try reader.readNextChunk()                                       // nonce
            for _ in 0..<publicKeyChunks { _ = try reader.readNextChunk() }      // public key fields
            _ = try reader.readNextBytes(as: UInt64.self)                        // serial
            _ = try reader.readNextBytes(as: UInt32.self)                        // certificate type (user/host)
            return normalize(try reader.readNextChunkAsString())
        } catch {
            return nil
        }
    }

    /// Number of length-prefixed public key fields between the nonce and the serial, per
    /// certificate algorithm (PROTOCOL.certkeys). Nil for algorithms not modelled here.
    private static func publicKeyChunkCount(forCertificateType type: String) -> Int? {
        switch type {
        case "ssh-ed25519-cert-v01@openssh.com": 1                              // pk
        case "ssh-rsa-cert-v01@openssh.com": 2                                  // e, n
        case "ecdsa-sha2-nistp256-cert-v01@openssh.com",
             "ecdsa-sha2-nistp384-cert-v01@openssh.com",
             "ecdsa-sha2-nistp521-cert-v01@openssh.com": 2                      // curve, point
        case "ssh-dss-cert-v01@openssh.com": 4                                  // p, q, g, y
        case "sk-ssh-ed25519-cert-v01@openssh.com": 2                          // pk, application
        case "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com": 3                  // curve, point, application
        default: nil
        }
    }

}

extension SignedDataContext {

    /// A localized clause appended to the approval prompt, or nil when the purpose is unknown.
    public var localizedPurpose: String? {
        switch self {
        case .userAuthentication(let user):
            String(localized: .authContextSignaturePurposeUserAuth(user: user))
        case .sshsig(let namespace):
            String(localized: .authContextSignaturePurposeSshsig(namespace: namespace))
        case .certificate(let keyID):
            if let keyID {
                String(localized: .authContextSignaturePurposeCertificate(keyID: keyID))
            } else {
                String(localized: .authContextSignaturePurposeCertificateUnnamed)
            }
        case .unknown:
            nil
        }
    }

}
