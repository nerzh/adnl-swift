import Foundation
import XCTest
import adnl_swift

final class ClientTests: XCTestCase {
    private func makeClient(_ transport: TestADNLTransport, limit: Int = 1024,
                            timeout: TimeInterval = 2) throws -> ADNLClient {
        try ADNLClient(host: "localhost", port: 1234, peerPublicKey: keyVectors[1].publicKey,
                       transport: transport, connectionTimeout: timeout, maximumPayloadSize: limit)
    }

    func testConfigurationAndConnectionStateValidation() async throws {
        let transport = TestADNLTransport()
        for port in [-1, 0, 65536] {
            XCTAssertThrowsError(try ADNLClient(host: "localhost", port: port,
                                              peerPublicKey: keyVectors[1].publicKey, transport: transport))
        }
        XCTAssertThrowsError(try ADNLClient(host: " ", port: 1, peerPublicKey: keyVectors[1].publicKey,
                                          transport: transport))
        XCTAssertThrowsError(try ADNLClient(host: "localhost", port: 1, peerPublicKey: Data(), transport: transport))
        for timeout in [0, -1, .infinity, .nan] {
            XCTAssertThrowsError(try makeClient(transport, timeout: timeout))
        }
        for limit in [-1, Int.max] { XCTAssertThrowsError(try makeClient(transport, limit: limit)) }
        let client = try makeClient(transport)
        await assertADNLError("not connected") { try await client.send(Data()) }
        await assertADNLError("not connected") { try await client.receive() }
        await client.close()
        await assertADNLError("more than once") { try await client.connect() }
    }

    func testFragmentedHandshakeAndConsecutiveMessages() async throws {
        let transport = TestADNLTransport(chunkSize: 1)
        let client = try ADNLClient(host: "localhost", port: 1234,
                                   peerPublicKey: keyVectors[1].publicKey.base64EncodedString(), transport: transport)
        try await client.connect()
        await assertADNLError("more than once") { try await client.connect() }
        for length in [0, 1, 15, 16, 17, 257] {
            let message = Data(repeating: UInt8(truncatingIfNeeded: length), count: length)
            try await client.send(nonzeroSlice(message))
            let received = try await client.receive()
            XCTAssertEqual(received, message)
        }
        await client.close()
        let endpoint = await transport.endpoint
        XCTAssertEqual(endpoint?.0, "localhost")
        XCTAssertEqual(endpoint?.1, 1234)
    }

    func testCoalescedAcknowledgementAndMessagesThenCleanEOF() async throws {
        let messages = [Data("first".utf8), Data(), Data("second".utf8)]
        let transport = TestADNLTransport(initialMessages: messages)
        let client = try makeClient(transport)
        try await client.connect()
        await transport.finishInput()
        for message in messages {
            let received = try await client.receive()
            XCTAssertEqual(received, message)
        }
        let readsBeforeEOF = await transport.readCount
        XCTAssertEqual(readsBeforeEOF, 1)
        let eof = try await client.receive()
        let repeatedEOF = try await client.receive()
        XCTAssertNil(eof)
        XCTAssertNil(repeatedEOF)
        let closed = await transport.closed
        XCTAssertTrue(closed)
    }

    func testInvalidAcknowledgementClosesConnection() async throws {
        let transport = TestADNLTransport(acknowledgement: Data([1]))
        let client = try makeClient(transport)
        await assertADNLError("empty acknowledgement") { try await client.connect() }
        let closed = await transport.closed
        XCTAssertTrue(closed)
    }

    func testInvalidAndOversizedHeadersFailBeforeReadingBody() async throws {
        for length: UInt32 in [0, 63, 97, UInt32.max] {
            let transport = TestADNLTransport()
            let client = try makeClient(transport, limit: 32)
            try await client.connect()
            let header = Data((0..<4).map { UInt8(truncatingIfNeeded: length >> ($0 * 8)) })
            try await transport.enqueuePlaintext(header)
            await assertADNLError(length < 64 ? "at least 64" : "configured limit") { try await client.receive() }
            let closed = await transport.closed
            let reads = await transport.readCount
            XCTAssertTrue(closed)
            XCTAssertEqual(reads, 2)
        }
    }

    func testCorruptedChecksumAndTruncatedEOF() async throws {
        for truncated in [false, true] {
            let transport = TestADNLTransport()
            let client = try makeClient(transport)
            try await client.connect()
            var packet = ADNLPacket(payload: Data([1, 2, 3])).data
            packet[packet.count - 1] ^= 1
            try await transport.enqueuePlaintext(truncated ? Data(packet.prefix(10)) : packet)
            await transport.finishInput()
            await assertADNLError(truncated ? "incomplete" : "Bad packet hash") { try await client.receive() }
            let closed = await transport.closed
            XCTAssertTrue(closed)
        }
    }

    func testSendLimitDoesNotConsumeCipherState() async throws {
        let transport = TestADNLTransport()
        let client = try makeClient(transport, limit: 3)
        try await client.connect()
        await assertADNLError("configured limit") { try await client.send(Data(repeating: 0, count: 4)) }
        try await client.send(Data([1, 2, 3]))
        let received = try await client.receive()
        XCTAssertEqual(received, Data([1, 2, 3]))
        await client.close()
    }

    func testReceiveCanRunAlongsideSendButNotAnotherReceive() async throws {
        let transport = TestADNLTransport()
        let client = try makeClient(transport)
        try await client.connect()
        let reader = Task { try await client.receive() }
        await transport.waitForRead()
        await assertADNLError("already in progress") { try await client.receive() }
        try await client.send(Data([7]))
        let received = try await reader.value
        XCTAssertEqual(received, Data([7]))
        await client.close()
    }

    func testCloseUnblocksReceiveAndIsIdempotent() async throws {
        let transport = TestADNLTransport()
        let client = try makeClient(transport)
        try await client.connect()
        let reader = Task { try await client.receive() }
        await transport.waitForRead()
        await client.close()
        await client.close()
        await assertADNLError("closed") { try await reader.value }
        let eof = try await client.receive()
        XCTAssertNil(eof)
    }

    func testCancellationUnblocksReceiveAndDiscardsConnection() async throws {
        let transport = TestADNLTransport()
        let client = try makeClient(transport)
        try await client.connect()
        let reader = Task { try await client.receive() }
        await transport.waitForRead()
        reader.cancel()
        do {
            _ = try await reader.value
            XCTFail("Expected cancellation")
        } catch { XCTAssertTrue(error is CancellationError) }
        let closed = await transport.closed
        XCTAssertTrue(closed)
    }

    func testConnectionTimeoutIncludesHandshakeAndUnblocksTransport() async throws {
        for stallConnect in [false, true] {
            let transport = TestADNLTransport(acknowledgement: nil, stallConnect: stallConnect)
            let client = try makeClient(transport, timeout: 0.02)
            await assertADNLError("timed out") { try await client.connect() }
            let closed = await transport.closed
            XCTAssertTrue(closed)
        }
    }

    func testWriteFailureIsTerminal() async throws {
        let transport = TestADNLTransport(failWrites: true)
        let client = try makeClient(transport)
        try await client.connect()
        await assertADNLError("Test write failure") { try await client.send(Data([1])) }
        await assertADNLError("Test write failure") { try await client.send(Data([2])) }
        let closed = await transport.closed
        XCTAssertTrue(closed)
    }

    func testCancellationWhileWaitingForHandshake() async throws {
        let transport = TestADNLTransport(acknowledgement: nil)
        let client = try makeClient(transport)
        let connecting = Task { try await client.connect() }
        await transport.waitForRead()
        connecting.cancel()
        do {
            try await connecting.value
            XCTFail("Expected cancellation")
        } catch { XCTAssertTrue(error is CancellationError) }
        let closed = await transport.closed
        XCTAssertTrue(closed)
    }

    func testOverlappingSendIsRejectedAndCancellationUnblocksWrite() async throws {
        let transport = TestADNLTransport(holdWrites: true)
        let client = try makeClient(transport)
        try await client.connect()
        let sending = Task { try await client.send(Data([1])) }
        await transport.waitForWrite()
        await assertADNLError("already in progress") { try await client.send(Data([2])) }
        sending.cancel()
        do {
            try await sending.value
            XCTFail("Expected cancellation")
        } catch { XCTAssertTrue(error is CancellationError) }
        let closed = await transport.closed
        XCTAssertTrue(closed)
    }
}

private actor TestADNLTransport: ADNLTransport {
    let chunkSize: Int?
    let initialMessages: [Data]
    let acknowledgement: Data?
    let stallConnect: Bool
    let failWrites: Bool
    let holdWrites: Bool
    var endpoint: (String, Int)?
    var readCount = 0
    var closed = false
    private var eof = false
    private var server: ADNLCipher?
    private var requests = Data()
    private var chunks: [Data] = []
    private var reader: CheckedContinuation<Data?, any Error>?
    private var connector: CheckedContinuation<Void, any Error>?
    private var writer: CheckedContinuation<Void, any Error>?
    private var readObservers: [CheckedContinuation<Void, Never>] = []
    private var writeObservers: [CheckedContinuation<Void, Never>] = []

    init(chunkSize: Int? = nil, initialMessages: [Data] = [], acknowledgement: Data? = Data(),
         stallConnect: Bool = false, failWrites: Bool = false, holdWrites: Bool = false) {
        self.chunkSize = chunkSize
        self.initialMessages = initialMessages
        self.acknowledgement = acknowledgement
        self.stallConnect = stallConnect
        self.failWrites = failWrites
        self.holdWrites = holdWrites
    }

    func connect(host: String, port: Int) async throws {
        endpoint = (host, port)
        if stallConnect { try await withCheckedThrowingContinuation { connector = $0 } }
    }

    func send(_ data: Data) async throws {
        guard !closed else { throw ADNLError("Test transport is closed.") }
        if let server {
            if failWrites { throw ADNLError("Test write failure") }
            if holdWrites {
                try await withCheckedThrowingContinuation {
                    writer = $0
                    let observers = writeObservers
                    writeObservers.removeAll()
                    observers.forEach { $0.resume() }
                }
            }
            requests.append(try server.decryptor.update(data))
            while let packet = try ADNLPacket.parse(data: requests) {
                requests.removeFirst(packet.length)
                enqueue(try server.encryptor.adnlSerializeMessage(data: packet.payload))
            }
        } else {
            let server = try ADNLHandshake.adnlHandshakeAssets(data, secretKey: keyVectors[1].seed.base64EncodedString())
            self.server = server
            guard let acknowledgement else { return }
            var output = try server.encryptor.adnlSerializeMessage(data: acknowledgement)
            for message in initialMessages {
                output.append(try server.encryptor.adnlSerializeMessage(data: message))
            }
            enqueue(output)
        }
    }

    func receive() async throws -> Data? {
        readCount += 1
        if !chunks.isEmpty { return nonzeroSlice(chunks.removeFirst()) }
        if closed || eof { return nil }
        return try await withCheckedThrowingContinuation {
            reader = $0
            let observers = readObservers
            readObservers.removeAll()
            observers.forEach { $0.resume() }
        }
    }

    func close() async {
        closed = true
        let reader = reader
        let connector = connector
        let writer = writer
        self.reader = nil
        self.connector = nil
        self.writer = nil
        reader?.resume(returning: nil)
        connector?.resume(throwing: ADNLError("Test transport is closed."))
        writer?.resume(throwing: ADNLError("Test transport is closed."))
    }

    func waitForRead() async {
        if reader != nil { return }
        await withCheckedContinuation { readObservers.append($0) }
    }

    func waitForWrite() async {
        if writer != nil { return }
        await withCheckedContinuation { writeObservers.append($0) }
    }

    func finishInput() {
        eof = true
        let pending = reader
        reader = nil
        pending?.resume(returning: nil)
    }

    func enqueuePlaintext(_ data: Data) throws {
        guard let server else { throw ADNLError("Test handshake is missing.") }
        enqueue(try server.encryptor.update(data))
    }

    private func enqueue(_ data: Data) {
        let size = chunkSize ?? data.count
        for offset in stride(from: 0, to: data.count, by: size) {
            chunks.append(Data(data.dropFirst(offset).prefix(size)))
        }
        if let reader, !chunks.isEmpty {
            self.reader = nil
            reader.resume(returning: nonzeroSlice(chunks.removeFirst()))
        }
    }
}
