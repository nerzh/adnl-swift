import Foundation

/// An ADNL-over-TCP client. Create a new instance after closing or losing a connection.
public actor ADNLClient {
    private enum State { case idle, connecting, connected, closed }

    private let host: String
    private let port: Int
    private let peerPublicKey: Data
    private let transport: any ADNLTransport
    private let connectionTimeout: TimeInterval
    private let maximumPayloadSize: Int
    private var state: State = .idle
    private var terminalError: (any Error)?
    private var cipher: ADNLCipher?
    private var encryptedInput = Data()
    private var frame = Data()
    private var sending = false
    private var receiving = false

    public init(
        host: String,
        port: Int,
        peerPublicKey: Data,
        transport: (any ADNLTransport)? = nil,
        connectionTimeout: TimeInterval = 10,
        maximumPayloadSize: Int = (1 << 24) - 64
    ) throws {
        guard !host.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              (1...65535).contains(port) else {
            throw ADNLError("A host and a port between 1 and 65535 are required.")
        }
        guard connectionTimeout.isFinite, connectionTimeout > 0, connectionTimeout <= 86_400 else {
            throw ADNLError("Connection timeout must be greater than zero and at most 86400 seconds.")
        }
        guard maximumPayloadSize >= 0,
              UInt64(maximumPayloadSize) <= UInt64(UInt32.max) - 64,
              maximumPayloadSize <= Int.max - 68 else {
            throw ADNLError("Maximum payload size is outside the supported packet size range.")
        }
        self.peerPublicKey = try ADNLAddress(publicKey: peerPublicKey).publicKey
        self.host = host
        self.port = port
        self.transport = transport ?? TCPTransport()
        self.connectionTimeout = connectionTimeout
        self.maximumPayloadSize = maximumPayloadSize
    }

    public init(
        host: String,
        port: Int,
        peerPublicKey: String,
        transport: (any ADNLTransport)? = nil,
        connectionTimeout: TimeInterval = 10,
        maximumPayloadSize: Int = (1 << 24) - 64
    ) throws {
        try self.init(host: host, port: port,
                      peerPublicKey: ADNLAddress(publicKey: peerPublicKey).publicKey,
                      transport: transport, connectionTimeout: connectionTimeout,
                      maximumPayloadSize: maximumPayloadSize)
    }

    /// Connect and complete the ADNL handshake, including the server's empty acknowledgement.
    public func connect() async throws {
        try Task.checkCancellation()
        guard state == .idle else { throw ADNLError("ADNL client cannot connect more than once.") }
        state = .connecting
        let timeout = UInt64(connectionTimeout * 1_000_000_000)
        let deadline = Task { [weak self] in
            do { try await Task.sleep(nanoseconds: timeout) } catch { return }
            await self?.connectionTimedOut()
        }
        defer { deadline.cancel() }
        do {
            try await withCancellation {
                let cipher = try ADNLCipher(peerPubKey: self.peerPublicKey.base64EncodedString(), mode: .client)
                self.cipher = cipher
                let handshake = try ADNLHandshake.adnlHandshake(keys: cipher.keys, params: cipher.params,
                                                                address: cipher.address)
                try await self.transport.connect(host: self.host, port: self.port)
                try self.checkOpen()
                try await self.transport.send(handshake)
                try self.checkOpen()
                guard let acknowledgement = try await self.readPacket(), acknowledgement.payload.isEmpty else {
                    throw ADNLError("ADNL handshake requires an empty acknowledgement from the server.")
                }
                self.state = .connected
            }
        } catch {
            await terminate(error: error)
            throw terminalError ?? error
        }
    }

    /// Send one payload. One send and one receive may run concurrently.
    public func send(_ payload: Data) async throws {
        try Task.checkCancellation()
        try checkConnected()
        guard !sending else { throw ADNLError("An ADNL send is already in progress.") }
        guard payload.count <= maximumPayloadSize else {
            throw ADNLError("ADNL payload exceeds the configured limit of \(maximumPayloadSize) bytes.")
        }
        sending = true
        defer { sending = false }
        do {
            try await withCancellation {
                guard let cipher = self.cipher else { throw ADNLError("ADNL client is closed.") }
                let data = try cipher.encryptor.adnlSerializeMessage(data: payload)
                try await self.transport.send(data)
                try self.checkOpen()
            }
        } catch {
            // A failed write may have sent a prefix; the cipher must never be reused.
            await terminate(error: error)
            throw terminalError ?? error
        }
    }

    /// Receive the next complete payload, including empty payloads. Returns nil at clean EOF.
    /// An incomplete packet at EOF is an error. Only one receive may be pending.
    public func receive() async throws -> Data? {
        try Task.checkCancellation()
        if state == .closed, terminalError == nil { return nil }
        try checkConnected()
        guard !receiving else { throw ADNLError("An ADNL receive is already in progress.") }
        receiving = true
        defer { receiving = false }
        do {
            return try await withCancellation {
                let packet = try await self.readPacket()
                if packet == nil { await self.terminate(error: nil) }
                return packet?.payload
            }
        } catch {
            await terminate(error: error)
            throw terminalError ?? error
        }
    }

    /// Permanently close this client and unblock pending operations.
    public func close() async {
        await terminate(error: nil)
    }

    private func readPacket() async throws -> ADNLPacket? {
        while true {
            try checkOpen()
            var targetLength = 4
            if let bodyLength = try ADNLPacket.bodyLength(in: frame) {
                guard bodyLength - 64 <= maximumPayloadSize else {
                    throw ADNLError("ADNL payload exceeds the configured limit of \(maximumPayloadSize) bytes.")
                }
                targetLength += bodyLength
                if frame.count == targetLength {
                    let packet = try ADNLPacket.parse(data: frame)
                    frame = Data()
                    return packet
                }
            }
            if encryptedInput.isEmpty {
                let chunk = try await transport.receive()
                try checkOpen()
                guard let chunk else {
                    guard frame.isEmpty else { throw ADNLError("Connection ended with an incomplete ADNL packet.") }
                    return nil
                }
                guard !chunk.isEmpty else {
                    throw ADNLError("ADNL transport returned an empty chunk instead of data or EOF.")
                }
                encryptedInput = chunk
            }
            guard let cipher else { throw ADNLError("ADNL client is closed.") }
            // Validate the decrypted header before reading or allocating the advertised body.
            let count = min(targetLength - frame.count, encryptedInput.count)
            frame.append(try cipher.decryptor.update(Data(encryptedInput.prefix(count))))
            encryptedInput.removeFirst(count)
        }
    }

    private func checkOpen() throws {
        try Task.checkCancellation()
        if let terminalError { throw terminalError }
        guard state == .connecting || state == .connected else { throw ADNLError("ADNL client is closed.") }
    }

    private func checkConnected() throws {
        if let terminalError { throw terminalError }
        guard state == .connected else { throw ADNLError("ADNL client is not connected.") }
    }

    private func connectionTimedOut() async {
        guard state == .connecting else { return }
        await terminate(error: ADNLError("ADNL connection and handshake timed out."))
    }

    private func terminate(error: (any Error)?) async {
        if state != .closed {
            state = .closed
            terminalError = error
            cipher = nil
            frame = Data()
            encryptedInput = Data()
        }
        await transport.close()
    }

    private func withCancellation<Value: Sendable>(_ operation: () async throws -> Value) async throws -> Value {
        try await withTaskCancellationHandler {
            try Task.checkCancellation()
            let value = try await operation()
            try Task.checkCancellation()
            return value
        } onCancel: {
            Task { await self.terminate(error: CancellationError()) }
        }
    }

    deinit {
        let transport = transport
        Task { await transport.close() }
    }
}
