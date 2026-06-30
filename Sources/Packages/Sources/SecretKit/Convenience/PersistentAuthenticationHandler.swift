import LocalAuthentication

/// A context describing a persisted authentication.
package final class PersistentAuthenticationContext<SecretType: Secret>: PersistedAuthenticationContext {

    /// The Secret to persist authentication for.
    let secret: SecretType
    /// The LAContext used to authorize the persistent context.
    package nonisolated(unsafe) let context: LAContext
    /// An expiration date for the context.
    /// - Note -  Monotonic time instead of Date() to prevent people setting the clock back.
    let monotonicExpiration: UInt64

    /// Initializes a context.
    /// - Parameters:
    ///   - secret: The Secret to persist authentication for.
    ///   - context: The LAContext used to authorize the persistent context.
    ///   - duration: The duration of the authorization context, in seconds.
    init(secret: SecretType, context: LAContext, duration: TimeInterval) {
        self.secret = secret
        unsafe self.context = context
        let durationInNanoSeconds = Measurement(value: duration, unit: UnitDuration.seconds).converted(to: .nanoseconds).value
        self.monotonicExpiration = clock_gettime_nsec_np(CLOCK_MONOTONIC) + UInt64(durationInNanoSeconds)
    }

    /// A boolean describing whether or not the context is still valid.
    package var valid: Bool {
        clock_gettime_nsec_np(CLOCK_MONOTONIC) < monotonicExpiration
    }

    package var expiration: Date {
        let remainingNanoseconds = monotonicExpiration - clock_gettime_nsec_np(CLOCK_MONOTONIC)
        let remainingInSeconds = Measurement(value: Double(remainingNanoseconds), unit: UnitDuration.nanoseconds).converted(to: .seconds).value
        return Date(timeIntervalSinceNow: remainingInSeconds)
    }
}

package actor PersistentAuthenticationHandler<SecretType: Secret>: Sendable {

    private var persistedAuthenticationContexts: [SecretType: PersistentAuthenticationContext<SecretType>] = [:]
    private var inProgressPersistenceCount = 0
    private var pendingSigningRetries: [CheckedContinuation<Void, Never>] = []

    package init() {
    }

    package func existingPersistedAuthenticationContext(secret: SecretType) -> PersistentAuthenticationContext<SecretType>? {
        guard let persisted = persistedAuthenticationContexts[secret], persisted.valid else { return nil }
        return persisted
    }

    package func persistAuthentication(secret: SecretType, forDuration duration: TimeInterval) async throws {
        inProgressPersistenceCount += 1
        defer { finishPersistence() }
        let newContext = LAContext()
        newContext.touchIDAuthenticationAllowableReuseDuration = duration
        newContext.localizedCancelTitle = String(localized: .authContextRequestDenyButton)

        let formatter = DateComponentsFormatter()
        formatter.unitsStyle = .spellOut
        formatter.allowedUnits = [.hour, .minute, .day]


        let durationString = formatter.string(from: duration)!
        newContext.localizedReason = String(localized: .authContextPersistForDuration(secretName: secret.name, duration: durationString))
        let success = try await newContext.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: newContext.localizedReason)
        guard success else { return }
        let context = PersistentAuthenticationContext(secret: secret, context: newContext, duration: duration)
        persistedAuthenticationContexts[secret] = context
    }

    /// Waits for an in-progress persistence authorization to settle.
    /// Establishing a persisted authorization opens a system prompt, which dismisses a signing
    /// prompt already on screen and fails that request. The dismissed request waits here, then
    /// signs again, reusing the persisted context if one was created.
    /// - Returns: whether a persistence authorization was in progress, meaning the caller should retry.
    package func awaitInProgressPersistence() async -> Bool {
        guard inProgressPersistenceCount > 0 else { return false }
        await withCheckedContinuation { continuation in
            pendingSigningRetries.append(continuation)
        }
        return true
    }

    private func finishPersistence() {
        inProgressPersistenceCount -= 1
        guard inProgressPersistenceCount == 0 else { return }
        let retries = pendingSigningRetries
        pendingSigningRetries.removeAll()
        for retry in retries {
            retry.resume()
        }
    }

}

