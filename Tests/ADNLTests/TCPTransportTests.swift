import Foundation
import NIOCore
import NIOEmbedded
import NIOPosix
import XCTest
@testable import adnl_swift

final class TCPTransportTests: XCTestCase {
    private func makeChannel() throws -> (TCPConnection, EmbeddedChannel) {
        let loop = EmbeddedEventLoop()
        let connection = TCPConnection(eventLoop: loop)
        let channel = EmbeddedChannel(handler: TCPInboundHandler(connection: connection), loop: loop)
        try channel.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 1234)).wait()
        return (connection, channel)
    }

    func testPendingReadAndBufferedReadPreserveBytes() throws {
        let (connection, channel) = try makeChannel()
        defer { _ = try? channel.finish(acceptAlreadyClosed: true) }
        let pending = connection.receive()
        try channel.writeInbound(ByteBuffer(bytes: [1, 2, 3]))
        XCTAssertEqual(try pending.wait(), Data([1, 2, 3]))
        try channel.writeInbound(ByteBuffer(bytes: [4, 5]))
        XCTAssertEqual(try connection.receive().wait(), Data([4, 5]))
        try connection.send(nonzeroSlice(Data([6, 7]))).wait()
        XCTAssertEqual(try channel.readOutbound(as: ByteBuffer.self), ByteBuffer(bytes: [6, 7]))
    }

    func testCloseUnblocksPendingReadAndRejectsWrites() throws {
        let (connection, channel) = try makeChannel()
        defer { _ = try? channel.finish(acceptAlreadyClosed: true) }
        let pending = connection.receive()
        XCTAssertThrowsError(try connection.receive().wait())
        let closing = connection.close()
        channel.embeddedEventLoop.run()
        try closing.wait()
        XCTAssertNil(try pending.wait())
        XCTAssertNil(try connection.receive().wait())
        XCTAssertThrowsError(try connection.send(Data([1])).wait())
        try connection.close().wait()
    }

    func testRemoteEOFDrainsBufferedData() throws {
        let (connection, channel) = try makeChannel()
        defer { _ = try? channel.finish(acceptAlreadyClosed: true) }
        try channel.writeInbound(ByteBuffer(bytes: [1]))
        try channel.close().wait()
        XCTAssertEqual(try connection.receive().wait(), Data([1]))
        XCTAssertNil(try connection.receive().wait())
    }

    func testPipelineErrorReachesPendingRead() throws {
        let (connection, channel) = try makeChannel()
        defer { _ = try? channel.finish(acceptAlreadyClosed: true) }
        let pending = connection.receive()
        channel.pipeline.fireErrorCaught(ADNLError("Test socket failure"))
        assertADNLError("Test socket failure") { try pending.wait() }
        assertADNLError("Test socket failure") { try connection.receive().wait() }
    }

    func testReceiveBufferIsBounded() throws {
        let (connection, channel) = try makeChannel()
        defer { _ = try? channel.finish(acceptAlreadyClosed: true) }
        try channel.writeInbound(ByteBuffer(bytes: [1]))
        try channel.writeInbound(ByteBuffer(bytes: [2]))
        assertADNLError("read limit") { try connection.receive().wait() }
        XCTAssertFalse(channel.isActive)
    }

    func testPublicTransportClosesPermanently() async throws {
        let transport = TCPTransport()
        await transport.close()
        await transport.close()
        await assertADNLError("cannot be reused") { try await transport.connect(host: "localhost", port: 1234) }
        await assertADNLError("not connected") { try await transport.send(Data([1])) }
        let eof = try await transport.receive()
        XCTAssertNil(eof)
    }

    func testDefaultClientAgainstLocalTCPServer() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let listener: any Channel
        do {
            listener = try await ServerBootstrap(group: group)
                .childChannelInitializer { channel in
                    channel.pipeline.addHandler(LocalADNLPeer())
                }
                .bind(host: "127.0.0.1", port: 0).get()
        } catch {
            try await group.shutdownGracefully()
            if let ioError = error as? IOError, [1, 13].contains(ioError.errnoCode) {
                throw XCTSkip("The environment does not allow binding a loopback TCP socket: \(error)")
            }
            throw error
        }
        let client = try ADNLClient(host: "127.0.0.1", port: XCTUnwrap(listener.localAddress?.port),
                                   peerPublicKey: keyVectors[1].publicKey, connectionTimeout: 2)
        do {
            try await client.connect()
            for payload in [Data([1]), Data(repeating: 0x42, count: 100_000), Data()] {
                try await client.send(payload)
                let response = try await client.receive()
                XCTAssertEqual(response, payload)
            }
            await client.close()
            try await listener.close().get()
            try await group.shutdownGracefully()
        } catch {
            await client.close()
            try? await listener.close().get()
            try? await group.shutdownGracefully()
            throw error
        }
    }
}

private final class LocalADNLPeer: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer
    private var handshake = Data()
    private var pending = Data()
    private var cipher: ADNLCipher?

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        do {
            var bytes = Data(unwrapInboundIn(data).readableBytesView)
            if cipher == nil {
                let needed = min(256 - handshake.count, bytes.count)
                handshake.append(bytes.prefix(needed))
                bytes.removeFirst(needed)
                guard handshake.count == 256 else { return }
                let server = try ADNLHandshake.adnlHandshakeAssets(handshake,
                                                                  secretKey: keyVectors[1].seed.base64EncodedString())
                cipher = server
                handshake = Data()
                write(try server.encryptor.adnlSerializeMessage(data: Data()), context: context)
            }
            guard let cipher else { return }
            pending.append(try cipher.decryptor.update(bytes))
            while let packet = try ADNLPacket.parse(data: pending) {
                pending.removeFirst(packet.length)
                write(try cipher.encryptor.adnlSerializeMessage(data: packet.payload), context: context)
            }
        } catch {
            context.close(promise: nil)
        }
    }

    private func write(_ data: Data, context: ChannelHandlerContext) {
        context.writeAndFlush(wrapOutboundOut(ByteBuffer(bytes: data)), promise: nil)
    }

    func errorCaught(context: ChannelHandlerContext, error: any Error) {
        context.close(promise: nil)
    }
}
