import Foundation
import Darwin

struct TunnelConfig: Codable {
    let host: String
    let port: Int
    let user: String
    let remotePort: Int
    func validate() throws {
        guard host.utf8.count <= 253, host.range(of: #"\A[A-Za-z0-9][A-Za-z0-9.-]*\z"#, options: .regularExpression) != nil,
              user.range(of: #"\A[a-z_][a-z0-9_-]{0,31}\z"#, options: .regularExpression) != nil,
              (1...65535).contains(port), (1024...65535).contains(remotePort) else { throw TunnelFailure.configuration }
    }
}
enum TunnelFailure: Error { case configuration, credentials, server, filesystem }
struct DeviceSettings: Decodable {
    let serverURL: String
    let deviceToken: String
    func validate() throws {
        guard let url = URLComponents(string: serverURL), url.scheme == "https", url.host != nil,
              url.user == nil, url.password == nil, url.query == nil, url.fragment == nil,
              url.path.isEmpty || url.path == "/", (32...512).contains(deviceToken.utf8.count),
              deviceToken.utf8.allSatisfy({ (33...126).contains($0) }) else { throw TunnelFailure.configuration }
    }
}
struct Control: Decodable {
    let enabled: Bool
    let expiresAt: String?
    let serverTimeUTC: String
    var persistent: Bool? = nil
}
let directory = "/Library/Application Support/OrbitTunnel"
let socketPath = directory + "/control"
let keyPath = directory + "/identity"
let hostsPath = directory + "/known_hosts"
func secureFile(_ path: String, privateFile: Bool = true) throws {
    var info = stat()
    guard lstat(path, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG, info.st_uid == 0,
          (info.st_mode & (privateFile ? 0o077 : 0o022)) == 0 else { throw TunnelFailure.filesystem }
}
func secureDirectory(_ path: String) throws {
    var info = stat()
    guard lstat(path, &info) == 0, (info.st_mode & S_IFMT) == S_IFDIR, info.st_uid == 0,
          info.st_mode & 0o022 == 0 else { throw TunnelFailure.filesystem }
}
func sshArguments(_ config: TunnelConfig) -> [String] {
    ["-F", "/dev/null", "-N", "-T", "-M", "-S", socketPath,
     "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "HostKeyAlias=orbit-tunnel-vps",
     "-o", "UserKnownHostsFile=\"\(hostsPath)\"", "-o", "GlobalKnownHostsFile=/dev/null",
     "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none", "-i", keyPath,
     "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no", "-o", "ForwardAgent=no",
     "-o", "ExitOnForwardFailure=yes", "-o", "ConnectTimeout=10",
     "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=2",
     "-R", "127.0.0.1:\(config.remotePort):127.0.0.1:2222", "-p", String(config.port), "-l", config.user, config.host]
}
func command(_ executable: String, _ arguments: [String]) -> Bool {
    let task = Process(); task.executableURL = URL(fileURLWithPath: executable); task.arguments = arguments
    task.standardInput = FileHandle.nullDevice; task.standardOutput = FileHandle.nullDevice; task.standardError = FileHandle.nullDevice
    do { try task.run(); task.waitUntilExit(); return task.terminationStatus == 0 } catch { return false }
}
final class NoRedirect: NSObject, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) { completionHandler(nil) }
}
func api(_ settings: DeviceSettings, _ path: String, body: [String: Any]? = nil) throws -> Data {
    let base = settings.serverURL.hasSuffix("/") ? String(settings.serverURL.dropLast()) : settings.serverURL
    guard let url = URL(string: base + path) else { throw TunnelFailure.configuration }
    var request = URLRequest(url: url, timeoutInterval: 10)
    request.httpMethod = body == nil ? "GET" : "POST"
    request.setValue("Bearer " + settings.deviceToken, forHTTPHeaderField: "Authorization")
    request.setValue("application/json", forHTTPHeaderField: "Content-Type")
    if let body { request.httpBody = try JSONSerialization.data(withJSONObject: body) }
    let session = URLSession(configuration: .ephemeral, delegate: NoRedirect(), delegateQueue: nil)
    defer { session.invalidateAndCancel() }
    let done = DispatchSemaphore(value: 0)
    let lock = NSLock()
    var result: Data?
    session.dataTask(with: request) { data, response, error in
        lock.lock(); defer { lock.unlock(); done.signal() }
        if error == nil, let http = response as? HTTPURLResponse, http.statusCode == 200,
           let data, data.count <= 65536 { result = data }
    }.resume()
    guard done.wait(timeout: .now() + 12) == .success else { throw TunnelFailure.server }
    lock.lock(); defer { lock.unlock() }
    guard let result else { throw TunnelFailure.server }
    return result
}
func parseDate(_ value: String) -> Date? {
    let formatter = ISO8601DateFormatter(); formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    if let date = formatter.date(from: value) { return date }
    formatter.formatOptions = [.withInternetDateTime]; return formatter.date(from: value)
}
func leaseDuration(_ control: Control) -> TimeInterval {
    guard control.enabled else { return 0 }
    guard let expiry = control.expiresAt, let end = parseDate(expiry),
          let now = parseDate(control.serverTimeUTC) else { return 0 }
    return max(0, min(3600, end.timeIntervalSince(now)))
}
if CommandLine.arguments.count == 3 && CommandLine.arguments[1] == "--check-config" {
    do {
        let config = try JSONDecoder().decode(TunnelConfig.self, from: Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[2])))
        try config.validate(); print("Valid tunnel configuration (files and connectivity not checked)"); exit(0)
    } catch { fputs("Invalid tunnel configuration\n", stderr); exit(1) }
}
guard geteuid() == 0 else { fputs("Run using the Orbit tunnel LaunchDaemon.\n", stderr); exit(1) }
umask(0o077)
if !FileManager.default.fileExists(atPath: directory + "/config.json") { exit(0) }
let config: TunnelConfig
let settings: DeviceSettings
do {
    for path in ["/Library", "/Library/Application Support", directory, "/Library/Application Support/Orbit"] { try secureDirectory(path) }
    for path in [directory + "/config.json", keyPath, hostsPath, "/Library/Application Support/Orbit/settings.json"] { try secureFile(path) }
    config = try JSONDecoder().decode(TunnelConfig.self, from: Data(contentsOf: URL(fileURLWithPath: directory + "/config.json")))
    settings = try JSONDecoder().decode(DeviceSettings.self, from: Data(contentsOf: URL(fileURLWithPath: "/Library/Application Support/Orbit/settings.json")))
    try config.validate(); try settings.validate()
} catch { fputs("Invalid tunnel provisioning or unsafe file permissions.\n", stderr); exit(1) }
// Stop a surviving control master from a previous helper instance. The root-only directory protects this socket.
_ = command("/usr/bin/ssh", ["-F", "/dev/null", "-S", socketPath, "-O", "exit", "orbit-tunnel-vps"])
// The independent watchdog expires access even while network requests are stalled.
// mach_continuous_time includes sleep, so sleeping cannot extend the one-hour window.
func continuousTime() -> TimeInterval {
    var scale = mach_timebase_info_data_t(); mach_timebase_info(&scale)
    return Double(mach_continuous_time()) * Double(scale.numer) / Double(scale.denom) / 1_000_000_000
}
final class TunnelState {
    let lock = NSRecursiveLock()
    var child: Process?
    var leaseEnd: TimeInterval = 0
    func stop() {
        lock.lock(); defer { lock.unlock() }
        if let child, child.isRunning {
            child.terminate()
            let deadline = continuousTime() + 2
            while child.isRunning && continuousTime() < deadline { Thread.sleep(forTimeInterval: 0.05) }
            if child.isRunning { kill(child.processIdentifier, SIGKILL) }
            child.waitUntilExit()
        }
        child = nil
    }
    func authorized() -> Bool { lock.lock(); defer { lock.unlock() }; return continuousTime() < leaseEnd }
    func updateLease(_ end: TimeInterval) { lock.lock(); defer { lock.unlock() }; leaseEnd = end; if !authorized() { stop() } }
    func running() -> Bool { lock.lock(); defer { lock.unlock() }; return child?.isRunning == true }
    func start(_ task: Process) throws {
        lock.lock(); defer { lock.unlock() }
        guard authorized() else { return }
        try task.run(); child = task
    }
}
let tunnel = TunnelState()
let watchdog = DispatchSource.makeTimerSource(queue: DispatchQueue.global(qos: .userInitiated))
watchdog.schedule(deadline: .now(), repeating: 0.25)
watchdog.setEventHandler { if !tunnel.authorized() { tunnel.stop() } }
watchdog.resume()
var nextAttempt: TimeInterval = 0
let hostname = ProcessInfo.processInfo.hostName
var url = URLComponents(); url.queryItems = [URLQueryItem(name: "hostname", value: hostname)]
while true {
    var note = ""
    do {
        let requestedAt = continuousTime()
        let data = try api(settings, "/api/device/remote-access?" + (url.percentEncodedQuery ?? ""))
        let control = try JSONDecoder().decode(Control.self, from: data)
        tunnel.updateLease(requestedAt + leaseDuration(control))

    } catch { note = "Control check failed; the tunnel will still close at its original expiration." }
    let requested = tunnel.authorized()
    let sshReady = command("/usr/bin/nc", ["-z", "-w", "1", "127.0.0.1", "2222"])
    if !requested || !sshReady { tunnel.stop() }
    if requested && sshReady && !tunnel.running() && continuousTime() >= nextAttempt {
        let task = Process(); task.executableURL = URL(fileURLWithPath: "/usr/bin/ssh"); task.arguments = sshArguments(config)
        task.standardInput = FileHandle.nullDevice; task.standardOutput = FileHandle.nullDevice; task.standardError = FileHandle.nullDevice
        do { try tunnel.start(task) } catch { note = "Unable to start SSH." }
        nextAttempt = continuousTime() + 15
    }
    let connected = tunnel.running() && command("/usr/bin/ssh", ["-F", "/dev/null", "-S", socketPath, "-O", "check", "orbit-tunnel-vps"])
    let status = connected ? "connected" : requested && !sshReady ? "error" : requested ? "connecting" : "disabled"
    if requested && !sshReady { note = "The private SSH listener is unavailable. Run secure tunnel setup again." }
    _ = try? api(settings, "/api/device/tunnel-status", body: ["hostname": hostname, "state": status,
        "sshReady": sshReady, "remotePort": config.remotePort, "message": note])
    Thread.sleep(forTimeInterval: 5)
}
