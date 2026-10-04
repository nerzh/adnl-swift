import Foundation
import NIOCore
import NIOPosix

/// A single-use TCP connection backed by Apple's SwiftNIO on Linux and Apple platforms.
public final class TCPTransport: ADNLTransport {
    private let connection: TCPConnection

    public init() {
        self.connection = TCPConnection(eventLoop: MultiThreadedEventLoopGroup.singleton.next())
    }

    public func connect(host: String, port: Int) async throws {
        try await perform { self.connection.connect(host: host, port: port) }
    }

    public func send(_ data: Data) async throws {
        try await perform { self.connection.send(data) }
    }

    public func receive() async throws -> Data? {
        try await perform { self.connection.receive() }
    }

    public func close() async {
        _ = try? await connection.eventLoop.flatSubmit { self.connection.close() }.get()
    }

    private func perform<Value: Sendable>(
        _ operation: @escaping @Sendable () -> EventLoopFuture<Value>
    ) async throws -> Value {
        try Task.checkCancellation()
        return try await withTaskCancellationHandler {
            let value = try await connection.eventLoop.flatSubmit(operation).get()
            try Task.checkCancellation()
            return value
        } onCancel: {
            self.connection.eventLoop.execute {
                _ = self.connection.close(error: CancellationError())
            }
        }
    }

    deinit {
        let connection = connection
        connection.eventLoop.execute { _ = connection.close() }
    }
}

// All mutable state is confined to eventLoop, including pipeline callbacks.
internal final class TCPConnection: @unchecked Sendable {
    let eventLoop: any EventLoop
    private var channel: (any Channel)?
    private var started = false
    private var connected = false
    private var closed = false
    private var error: (any Error)?
    private var connecting: EventLoopPromise<Void>?
    private var reading: EventLoopPromise<Data?>?
    private var buffered: Data?

    init(eventLoop: any EventLoop) {
        self.eventLoop = eventLoop
    }

    func connect(host: String, port: Int) -> EventLoopFuture<Void> {
        eventLoop.preconditionInEventLoop()
        guard !closed, !started else {
            return eventLoop.makeFailedFuture(ADNLError("TCP transport cannot be reused."))
        }
        guard !host.isEmpty, (1...65535).contains(port) else {
            return eventLoop.makeFailedFuture(ADNLError("A host and a port between 1 and 65535 are required."))
        }
        started = true
        let promise = eventLoop.makePromise(of: Void.self)
        connecting = promise
        ClientBootstrap(group: eventLoop)
            .connectTimeout(.seconds(10))
            .channelOption(ChannelOptions.autoRead, value: false)
            .channelOption(ChannelOptions.maxMessagesPerRead, value: 1)
            .channelOption(ChannelOptions.recvAllocator, value: FixedSizeRecvByteBufferAllocator(capacity: 64 * 1024))
            .channelInitializer { channel in
                guard !self.closed else {
                    return channel.eventLoop.makeFailedFuture(ADNLError("TCP transport is closed."))
                }
                return channel.pipeline.addHandler(TCPInboundHandler(connection: self))
            }
            .connect(host: host, port: port)
            .whenComplete { result in
                switch result {
                case .success(let channel):
                    guard !self.closed else {
                        channel.close(promise: nil)
                        return
                    }
                    let pending = self.connecting
                    self.connecting = nil
                    pending?.succeed(())
                case .failure(let error):
                    _ = self.close(error: error)
                }
            }
        return promise.futureResult
    }

    func handlerAdded(channel: any Channel) {
        eventLoop.preconditionInEventLoop()
        self.channel = channel
    }

    func channelActive() {
        eventLoop.preconditionInEventLoop()
        connected = true
    }

    func send(_ data: Data) -> EventLoopFuture<Void> {
        eventLoop.preconditionInEventLoop()
        guard connected, !closed, let channel else {
            return eventLoop.makeFailedFuture(error ?? ADNLError("TCP transport is not connected."))
        }
        var buffer = channel.allocator.buffer(capacity: data.count)
        buffer.writeBytes(data)
        return channel.writeAndFlush(buffer)
    }

    func receive() -> EventLoopFuture<Data?> {
        eventLoop.preconditionInEventLoop()
        if let error { return eventLoop.makeFailedFuture(error) }
        if let buffered {
            self.buffered = nil
            return eventLoop.makeSucceededFuture(buffered)
        }
        if closed { return eventLoop.makeSucceededFuture(nil) }
        guard connected, let channel else {
            return eventLoop.makeFailedFuture(ADNLError("TCP transport is not connected."))
        }
        guard reading == nil else {
            return eventLoop.makeFailedFuture(ADNLError("A TCP receive is already in progress."))
        }
        let promise = eventLoop.makePromise(of: Data?.self)
        reading = promise
        // Demand-driven reads keep incoming data bounded when the consumer is slow.
        channel.read()
        return promise.futureResult
    }

    func received(_ data: Data) {
        eventLoop.preconditionInEventLoop()
        guard !closed, !data.isEmpty else { return }
        if let pending = reading {
            reading = nil
            pending.succeed(data)
        } else if buffered == nil {
            buffered = data
        } else {
            _ = close(error: ADNLError("TCP receive buffer exceeded its read limit."))
        }
    }

    func readComplete() {
        eventLoop.preconditionInEventLoop()
        if reading != nil, !closed { channel?.read() }
    }

    func close(error: (any Error)? = nil) -> EventLoopFuture<Void> {
        eventLoop.preconditionInEventLoop()
        guard !closed else { return eventLoop.makeSucceededFuture(()) }
        closed = true
        self.error = error
        if error != nil { buffered = nil }
        let pendingConnect = connecting
        let pendingRead = reading
        connecting = nil
        reading = nil
        pendingConnect?.fail(error ?? ADNLError("TCP transport closed while connecting."))
        if let error {
            pendingRead?.fail(error)
        } else {
            pendingRead?.succeed(nil)
        }
        guard let channel else { return eventLoop.makeSucceededFuture(()) }
        self.channel = nil
        channel.close(promise: nil)
        return channel.closeFuture
    }
}

internal final class TCPInboundHandler: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer
    private let connection: TCPConnection

    init(connection: TCPConnection) { self.connection = connection }

    func handlerAdded(context: ChannelHandlerContext) {
        connection.handlerAdded(channel: context.channel)
    }

    func channelActive(context: ChannelHandlerContext) {
        connection.channelActive()
        context.fireChannelActive()
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        connection.received(Data(unwrapInboundIn(data).readableBytesView))
    }

    func channelReadComplete(context: ChannelHandlerContext) {
        connection.readComplete()
    }

    func channelInactive(context: ChannelHandlerContext) {
        _ = connection.close()
        context.fireChannelInactive()
    }

    func errorCaught(context: ChannelHandlerContext, error: any Error) {
        _ = connection.close(error: error)
    }
}
