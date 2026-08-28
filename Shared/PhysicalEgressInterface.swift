import Darwin
import Dispatch
import Foundation
import Network

private final class PhysicalEgressResolutionState: @unchecked Sendable {
    let semaphore = DispatchSemaphore(value: 0)

    private let lock = NSLock()
    private var completed = false
    private var resolvedName: String?

    func complete(with name: String?) {
        lock.lock()
        guard !completed else {
            lock.unlock()
            return
        }
        completed = true
        resolvedName = name
        lock.unlock()
        semaphore.signal()
    }

    func result() -> String? {
        lock.lock()
        let value = resolvedName
        lock.unlock()
        return value
    }
}

enum PhysicalEgressInterface {
    static func resolve(timeout: DispatchTimeInterval = .seconds(2)) -> String? {
        let state = PhysicalEgressResolutionState()
        let monitor = NWPathMonitor()
        monitor.pathUpdateHandler = { path in
            guard path.status == .satisfied else { return }
            let name = path.availableInterfaces.first { candidate in
                switch candidate.type {
                case .wifi, .cellular, .wiredEthernet:
                    return true
                default:
                    return false
                }
            }?.name
            state.complete(with: name.flatMap { isValidName($0) ? $0 : nil })
        }
        monitor.start(queue: DispatchQueue(
            label: "com.example.tunnelclient.egress-path",
            qos: .userInitiated
        ))
        defer { monitor.cancel() }

        guard state.semaphore.wait(timeout: .now() + timeout) == .success else {
            return nil
        }
        return state.result()
    }

    static func isValidName(_ value: String) -> Bool {
        guard !value.isEmpty, value.utf8.count < Int(IFNAMSIZ) else { return false }
        return value.unicodeScalars.allSatisfy {
            CharacterSet.alphanumerics.contains($0) || "._-".unicodeScalars.contains($0)
        }
    }
}
