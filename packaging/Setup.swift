import Foundation
import Darwin

struct Credentials: Codable {
    let serverURL: String
    let deviceToken: String
    let activityToken: String
    func validate() throws {
        guard let url = URLComponents(string: serverURL), url.scheme == "https",
              let host = url.host, !host.isEmpty, url.user == nil, url.password == nil,
              url.query == nil, url.fragment == nil, url.path.isEmpty || url.path == "/",
              deviceToken != activityToken,
              [deviceToken, activityToken].allSatisfy({ token in
                  (32...512).contains(token.utf8.count) && token.utf8.allSatisfy { (33...126).contains($0) }
              }) else { throw SetupError.message("Invalid server or tokens. Use distinct device and activity tokens from the VPS.") }
    }
}
// The user-owned monitor must never receive the privileged daemon token.
struct MonitorCredentials: Codable {
    let serverURL: String
    let activityToken: String
    func validate() throws {
        guard let url = URLComponents(string: serverURL), url.scheme == "https",
              let host = url.host, !host.isEmpty, url.user == nil, url.password == nil,
              url.query == nil, url.fragment == nil, url.path.isEmpty || url.path == "/",
              (32...512).contains(activityToken.utf8.count),
              activityToken.utf8.allSatisfy({ (33...126).contains($0) }) else {
            throw SetupError.message("Invalid monitor server or activity token")
        }
    }
}

func origin(_ value: String) throws -> String {
    guard var url = URLComponents(string: value), url.scheme == "https",
          let host = url.host, !host.isEmpty, url.user == nil, url.password == nil,
          url.query == nil, url.fragment == nil, url.path.isEmpty || url.path == "/" else {
        throw SetupError.message("Invalid configured server origin")
    }
    url.host = host.lowercased()
    url.path = ""
    if url.port == 443 { url.port = nil }
    guard let result = url.string else { throw SetupError.message("Invalid configured server origin") }
    return result
}

func checkExistingConfiguration(settings: URL, cache: URL, serverURL: String) throws {
    let fm = FileManager.default
    guard fm.fileExists(atPath: settings.path) else {
        if fm.fileExists(atPath: cache.path) {
            throw SetupError.message("Cached policy has no server settings. Review it before reconfiguration.")
        }
        return
    }
    let data = try Data(contentsOf: settings)
    guard let object = try JSONSerialization.jsonObject(with: data) as? [String: String],
          object["deviceToken"] != nil else {
        throw SetupError.message("Existing Orbit settings are invalid; review them before reconfiguration")
    }
    let previous = object["serverURL"] ?? "https://orbit.side-forge.com"
    guard try origin(previous) == origin(serverURL) else {
        throw SetupError.message("This Mac is configured for another server. Review its cached policy before switching servers.")
    }
}

enum SetupError: Error { case message(String) }

final class SSHInstallerLock {
    private var descriptor: Int32 = -1
    init(path: String = "/var/run/com.side-forge.orbit.ssh-installer.lock", owner: uid_t = 0) throws {
        let fd = open(path, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw SetupError.message("Cannot open the SSH installer lock") }
        do {
            var info = stat()
            guard fstat(fd, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG,
                  info.st_uid == owner, info.st_mode & 0o077 == 0, info.st_nlink == 1 else {
                throw SetupError.message("Unsafe SSH installer lock file; inspect its ownership and permissions")
            }
            guard flock(fd, LOCK_EX | LOCK_NB) == 0 else {
                throw SetupError.message("Another SSH installation is already running, or its lock is unavailable")
            }
            descriptor = fd
        } catch { close(fd); throw error }
    }
    deinit { if descriptor >= 0 { close(descriptor) } }
}

func validateTargetAccount(uid: uid_t, home: String) throws {
    let normalized = URL(fileURLWithPath:home).standardizedFileURL.path
    guard uid >= 501, uid <= UInt32(Int32.max), home.hasPrefix("/"),
          !["/", "/var/empty", "/private/var/empty", "/Users/Shared"].contains(normalized) else {
        throw SetupError.message("Select a regular Mac account with a private home directory")
    }
}

func validateUserHome(_ home: String) throws {
    var info = stat()
    guard stat(home, &info) == 0, (info.st_mode & S_IFMT) == S_IFDIR,
          access(home, W_OK | X_OK) == 0 else {
        throw SetupError.message("The target user's home directory is unavailable or not writable; unlock it or fix its permissions before installing")
    }
}

@discardableResult
func run(_ executable: String, _ arguments: [String], input: Data? = nil, capture: Bool = false) throws -> String {
    guard (input?.count ?? 0) <= 8192 else { throw SetupError.message("Command input too large") }
    let process = Process()
    process.executableURL = URL(fileURLWithPath: executable)
    process.arguments = arguments
    let output = capture ? Pipe() : nil
    let pipe = input == nil ? nil : Pipe()
    defer {
        for stream in [output, pipe].compactMap({ $0 }) {
            try? stream.fileHandleForReading.close()
            try? stream.fileHandleForWriting.close()
        }
    }
    if let output { process.standardOutput = output }
    if let pipe {
        // Treat a child rejecting stdin as an ordinary error, never SIGPIPE termination.
        guard fcntl(pipe.fileHandleForWriting.fileDescriptor, F_SETNOSIGPIPE, 1) != -1 else { throw SetupError.message("Cannot protect credential input pipe") }
        process.standardInput = pipe
    }
    try process.run()
    try? output?.fileHandleForWriting.close()
    try? pipe?.fileHandleForReading.close()
    if let input, let pipe {
        do {
            try pipe.fileHandleForWriting.write(contentsOf:input)
            try pipe.fileHandleForWriting.close()
        } catch {
            if process.isRunning {
                process.terminate()
                let deadline = Date().addingTimeInterval(2)
                while process.isRunning && Date() < deadline { Thread.sleep(forTimeInterval:0.02) }
                if process.isRunning { kill(process.processIdentifier, SIGKILL) }
            }
            process.waitUntilExit()
            throw SetupError.message("Command rejected credential input: " + URL(fileURLWithPath:executable).lastPathComponent)
        }
    }
    let result = output?.fileHandleForReading.readDataToEndOfFile() ?? Data()
    process.waitUntilExit()
    guard process.terminationStatus == 0 else {
        throw SetupError.message("Command failed: \(URL(fileURLWithPath: executable).lastPathComponent) (\(process.terminationStatus))")
    }
    return String(data: result, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
}

func privateJSON(_ object: [String: String], at path: String) throws {
    let data = try JSONSerialization.data(withJSONObject: object)
    try data.write(to: URL(fileURLWithPath: path), options: .atomic)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path)
}

func readInputData() throws -> Data {
    var data = Data()
    while true {
        let chunk = FileHandle.standardInput.readData(ofLength: min(4096, 8193 - data.count))
        if chunk.isEmpty { return data }
        data.append(chunk)
        guard data.count <= 8192 else { throw SetupError.message("Credential input too large") }
    }
}

func readInput() throws -> Credentials {
    let credentials = try JSONDecoder().decode(Credentials.self, from: readInputData())
    try credentials.validate()
    return credentials
}

func readMonitorInput() throws -> MonitorCredentials {
    let credentials = try JSONDecoder().decode(MonitorCredentials.self, from: readInputData())
    try credentials.validate()
    return credentials
}

func monitorSetup(deferIfLoggedOut: Bool = false) throws {
    guard getuid() >= 501, let user = getpwuid(getuid()) else {
        throw SetupError.message("Tracker setup must run as the target user")
    }
    let home = String(cString:user.pointee.pw_dir)
    try validateTargetAccount(uid:getuid(), home:home)
    try validateUserHome(home)
    let input = try readInputData()
    let credentials = try JSONDecoder().decode(MonitorCredentials.self, from: input)
    try credentials.validate()
    let profile: Data?
    if deferIfLoggedOut {
        let fields = try JSONSerialization.jsonObject(with: input) as? [String: String] ?? [:]
        profile = try chromeProfile(extensionID: fields["extensionID"] ?? "", serverURL: credentials.serverURL, browserToken: fields["browserToken"] ?? "")
    } else { profile = nil }
    let fm = FileManager.default
    let directory = home + "/Library/Application Support/Orbit"
    let agents = home + "/Library/LaunchAgents"
    try fm.createDirectory(atPath: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    try fm.createDirectory(atPath: agents, withIntermediateDirectories: true)
    try privateJSON(["serverURL": credentials.serverURL, "activityToken": credentials.activityToken],
                    at: directory + "/monitor-settings.json")
    let label = "com.side-forge.orbit.foreground"
    let plist = agents + "/" + label + ".plist"
    let properties: [String: Any] = ["Label": label,
        "ProgramArguments": ["/usr/local/libexec/orbit-foreground"],
        "RunAtLoad": true, "KeepAlive": true, "ThrottleInterval": 15]
    let data = try PropertyListSerialization.data(fromPropertyList: properties, format: .xml, options: 0)
    try data.write(to: URL(fileURLWithPath: plist), options: .atomic)
    try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: plist)
    if let profile {
        try profile.write(to: URL(fileURLWithPath: directory + "/Orbit-Chrome.mobileconfig"), options: .atomic)
        try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: directory + "/Orbit-Chrome.mobileconfig")
    }
    if try !startMonitor(uid:getuid(), plist:plist, deferIfLoggedOut:deferIfLoggedOut) {
        print("Tracker configured; it will start at this user's next desktop login.")
    }

}

func startMonitor(uid: uid_t, plist: String, deferIfLoggedOut: Bool, command: (String, [String], Bool) throws -> String = { try run($0, $1, capture:$2) }) throws -> Bool {
    let domain = "gui/\(uid)", label = "com.side-forge.orbit.foreground"
    if deferIfLoggedOut && (try? command("/bin/launchctl", ["print", domain], true)) == nil { return false }
    if (try? command("/bin/launchctl", ["print", domain + "/" + label], true)) != nil {
        _ = try command("/bin/launchctl", ["bootout", domain + "/" + label], false)
    }
    _ = try command("/bin/launchctl", ["enable", domain + "/" + label], false)
    _ = try command("/bin/launchctl", ["bootstrap", domain, plist], false)
    _ = try command("/bin/launchctl", ["kickstart", domain + "/" + label], false)
    return true
}

func validToken(_ value: String?) -> Bool {
    guard let value = value else { return false }
    return (32...512).contains(value.utf8.count) && value.utf8.allSatisfy { (33...126).contains($0) }
}

func savedDevice() throws -> [String: String] {
    guard getuid() == 0 else { throw SetupError.message("Saved device settings require administrator authorization") }
    let directory = "/Library/Application Support/Orbit"
    for path in [directory, directory + "/settings.json"] {
        var info = stat()
        if lstat(path, &info) != 0 {
            if errno == ENOENT { return [:] }
            throw SetupError.message("Cannot inspect saved device settings")
        }
        let expected = path == directory ? S_IFDIR : S_IFREG
        guard info.st_uid == 0, (info.st_mode & S_IFMT) == expected,
              (info.st_mode & 0o022) == 0, path == directory || info.st_size <= 8192 else {
            throw SetupError.message("Unsafe saved device settings; inspect ownership and permissions")
        }
    }
    let data = try Data(contentsOf: URL(fileURLWithPath: directory + "/settings.json"))
    return (try? JSONSerialization.jsonObject(with: data) as? [String: String]) ?? [:]
}

func deviceMetadata(_ saved: [String: String]) throws -> [String: String] {
    let server = try origin(saved["serverURL"] ?? "https://orbit.side-forge.com")
    // Never expose the privileged DEVICE token to the desktop user.
    return ["serverURL": server, "reuseDevice": validToken(saved["deviceToken"]) ? "true" : "false"]
}

func savedUserSettings(home: String, serverURL: String) -> [String: String] {
    let directory = URL(fileURLWithPath: home).appendingPathComponent("Library/Application Support/Orbit")
    var result: [String: String] = [:]
    if let data = try? Data(contentsOf: directory.appendingPathComponent("monitor-settings.json")),
       let monitor = try? JSONDecoder().decode(MonitorCredentials.self, from: data),
       (try? monitor.validate()) != nil,
       (try? origin(monitor.serverURL)) == (try? origin(serverURL)) {
        result["activityToken"] = monitor.activityToken
    }
    if let data = try? Data(contentsOf: directory.appendingPathComponent("Orbit-Chrome.mobileconfig")),
       let object = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil),
       let profile = object as? [String: Any],
       profile["PayloadIdentifier"] as? String == "com.side-forge.orbit.chrome.configuration",
       let payloads = profile["PayloadContent"] as? [[String: Any]] {
        for payload in payloads {
            guard let domains = payload["PayloadContent"] as? [String: Any] else { continue }
            for (domain, value) in domains where domain.hasPrefix("com.google.Chrome.extensions.") {
                guard let configuration = value as? [String: Any],
                      let forced = configuration["Forced"] as? [[String: Any]],
                      let settings = forced.first?["mcx_preference_settings"] as? [String: String],
                      let server = settings["serverURL"], let token = settings["browserToken"],
                      (try? origin(server)) == (try? origin(serverURL)), validToken(token) else { continue }
                let id = String(domain.dropFirst("com.google.Chrome.extensions.".count))
                if (try? chromeProfile(extensionID: id, serverURL: server, browserToken: token)) != nil {
                    result["extensionID"] = id
                    result["browserToken"] = token
                }
            }
        }
    }
    return result
}

func prepareInstall() throws {
    guard getuid() == 0 else { throw SetupError.message("Installer preparation requires administrator authorization") }
    let service = "system/com.side-forge.orbit.updater"
    if (try? run("/bin/launchctl", ["print", service], capture: true)) != nil {
        try run("/bin/launchctl", ["bootout", service])
    }
    if FileManager.default.fileExists(atPath: "/Library/PrivilegedHelperTools/orbit-updater") {
        try run("/Library/PrivilegedHelperTools/orbit-updater", ["--recover-only"])
    } else if FileManager.default.fileExists(atPath: "/Library/Application Support/OrbitUpdates/transaction") {
        throw SetupError.message("Pending update from an older updater. Recover it with that version before upgrading or uninstalling.")
    }
}

func startUpdater(command: (String, [String], Bool) throws -> String = { try run($0, $1, capture: $2) }) throws {
    let enabled = try command("/Library/PrivilegedHelperTools/orbit-updater", ["--setup"], true) == "enabled"
    if enabled {
        _ = try command("/bin/launchctl", ["enable", "system/com.side-forge.orbit.updater"], false)
        _ = try command("/bin/launchctl", ["bootstrap", "system", "/Library/LaunchDaemons/com.side-forge.orbit.updater.plist"], false)
        print("Automatic signed updates enabled (hourly checks).")
    } else {
        // Merely omitting bootstrap does not prevent a LaunchDaemon plist from
        // loading at the next reboot. Persist an explicit disabled override.
        _ = try command("/bin/launchctl", ["disable", "system/com.side-forge.orbit.updater"], false)
        print("Automatic updates disabled: no release-signing public key configured.")
    }
}

func configure(_ username: String, reuseDevice: Bool = false, headless: Bool = false) throws {
    guard getuid() == 0, let user = getpwnam(username), user.pointee.pw_uid >= 501 else {
        throw SetupError.message("Configuration requires administrator authorization and a regular target user")
    }
    let uid = user.pointee.pw_uid
    try validateTargetAccount(uid:uid, home:String(cString:user.pointee.pw_dir))
    if !headless {
        let console = try run("/usr/bin/stat", ["-f", "%Su", "/dev/console"], capture: true)
        guard console == username else { throw SetupError.message("Log into the target user's desktop before installing") }
    }
    let input = try readInputData()
    let supplied = try JSONDecoder().decode(Credentials.self, from: input)
    let credentials: Credentials
    if reuseDevice {
        let saved = try savedDevice()
        guard validToken(saved["deviceToken"]),
              try origin(saved["serverURL"] ?? "https://orbit.side-forge.com") == origin(supplied.serverURL) else {
            throw SetupError.message("Saved device settings changed; restart the installer")
        }
        credentials = Credentials(serverURL: supplied.serverURL, deviceToken: saved["deviceToken"]!, activityToken: supplied.activityToken)
    } else { credentials = supplied }
    try credentials.validate()
    if let fields = try JSONSerialization.jsonObject(with: input) as? [String: String],
       let browser = fields["browserToken"], browser == credentials.deviceToken || browser == credentials.activityToken {
        throw SetupError.message("The BROWSER token must differ from DEVICE and ACTIVITY tokens")
    }
    let extra = try JSONSerialization.jsonObject(with: input) as? [String: String] ?? [:]
    if headless { _ = try chromeProfile(extensionID: extra["extensionID"] ?? "", serverURL: credentials.serverURL, browserToken: extra["browserToken"] ?? "") }
    let directory = "/Library/Application Support/Orbit"
    let fm = FileManager.default
    var status = stat()
    if lstat(directory, &status) == 0 {
        guard status.st_uid == 0, (status.st_mode & S_IFMT) == S_IFDIR,
              (status.st_mode & 0o022) == 0 else {
            throw SetupError.message("Unsafe Orbit settings directory; inspect its ownership and permissions")
        }
    } else {
        try fm.createDirectory(atPath: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    }
    let settings = directory + "/settings.json"
    // Refuse stale-policy reuse even if the old settings are missing or corrupt.
    try checkExistingConfiguration(settings: URL(fileURLWithPath: settings),
        cache: URL(fileURLWithPath: directory + "/policy.json"), serverURL: credentials.serverURL)
    try privateJSON(["serverURL": credentials.serverURL, "deviceToken": credentials.deviceToken], at: settings)
    if (try? run("/bin/launchctl", ["print", "system/com.side-forge.orbit.agent"], capture: true)) != nil {
        try run("/bin/launchctl", ["bootout", "system/com.side-forge.orbit.agent"])
    }
    try run("/bin/launchctl", ["enable", "system/com.side-forge.orbit.agent"])
    try run("/bin/launchctl", ["bootstrap", "system", "/Library/LaunchDaemons/com.side-forge.orbit.agent.plist"])
    try run("/bin/launchctl", ["kickstart", "system/com.side-forge.orbit.agent"])
    // Drop privileges before writing anything in the target user's home.
    var monitor: [String: String] = ["serverURL": credentials.serverURL, "activityToken": credentials.activityToken]
    if headless { monitor["browserToken"] = extra["browserToken"]; monitor["extensionID"] = extra["extensionID"] }
    let data = try JSONSerialization.data(withJSONObject: monitor)
    var command = ["/usr/bin/sudo", "-n", "-H", "-u", username, "/usr/local/libexec/orbit-setup", headless ? "--monitor-user-headless" : "--monitor-user"]
    if !headless || (try? run("/bin/launchctl", ["print", "gui/\(uid)"], capture: true)) != nil {
        command = ["/bin/launchctl", "asuser", String(uid)] + command
    }
    try run(command[0], Array(command.dropFirst()), input: data)
    try startUpdater()
}

func shellQuote(_ value: String) -> String { "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'" }

func stagePackage(_ source: URL, in directory: URL) throws -> URL {
    let fm = FileManager.default
    let source = source.standardizedFileURL.resolvingSymlinksInPath()
    let values = try source.resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey])
    guard values.isRegularFile == true, (values.fileSize ?? 0) > 0 else {
        throw SetupError.message("Orbit.pkg is missing or empty. Extract the entire installer ZIP first.")
    }
    let staged = directory.appendingPathComponent("Orbit.pkg")
    try fm.copyItem(at: source, to: staged)
    try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: staged.path)
    let expanded = directory.appendingPathComponent("package-check")
    do {
        // Read-only validation, before asking for tokens or administrator access.
        try run("/usr/sbin/pkgutil", ["--expand", staged.path, expanded.path], capture: true)
        try fm.removeItem(at: expanded)
    } catch {
        throw SetupError.message("Orbit.pkg is not a readable installer package. Download the installer ZIP again and extract the entire folder.")
    }
    return staged
}

// Generate in the logged-in user's private directory; the containing profile
// requests System scope, so macOS requires administrator approval to activate it.
func chromeProfile(extensionID: String, serverURL: String, browserToken: String) throws -> Data {
    guard extensionID.utf8.count == 32,
          extensionID.utf8.allSatisfy({ (97...112).contains($0) }),
          (32...512).contains(browserToken.utf8.count),
          browserToken.utf8.allSatisfy({ (33...126).contains($0) }) else {
        throw SetupError.message("Use a real 32-letter Chrome Web Store extension ID and a valid BROWSER token")
    }
    _ = try origin(serverURL)
    func payload(_ type: String, _ identifier: String, _ values: [String: Any]) -> [String: Any] {
        var result = values
        result.merge(["PayloadType": type, "PayloadVersion": 1,
                      "PayloadIdentifier": identifier, "PayloadUUID": UUID().uuidString]) { _, new in new }
        return result
    }
    let chromeSettings: [String: Any] = [
        "ExtensionSettings": [extensionID: ["installation_mode": "force_installed",
            "update_url": "https://clients2.google.com/service/update2/crx"]],
        "IncognitoModeAvailability": 1, "BrowserGuestModeEnabled": false]
    // Use Apple's documented managed-preferences payload format. Arbitrary
    // bundle IDs are preference domains, not registered Apple payload types.
    func managed(_ domain: String, _ identifier: String, _ values: [String: Any]) -> [String: Any] {
        payload("com.apple.ManagedClient.preferences", identifier, [
            "PayloadContent": [domain: ["Forced": [["mcx_preference_settings": values]]]]])
    }
    let chrome = managed("com.google.Chrome", "com.side-forge.orbit.chrome.policy", chromeSettings)
    let storage = managed("com.google.Chrome.extensions." + extensionID,
        "com.side-forge.orbit.chrome.storage", ["serverURL": serverURL, "browserToken": browserToken])
    let profile = payload("Configuration", "com.side-forge.orbit.chrome.configuration", [
        "PayloadDisplayName": "Orbit Chrome Browser Policy", "PayloadOrganization": "Orbit",
        "PayloadScope": "System", "PayloadRemovalDisallowed": false,
        "PayloadContent": [chrome, storage]])
    return try PropertyListSerialization.data(fromPropertyList: profile, format: .xml, options: 0)
}

struct CLIOptions {
    let package: String
    let username: String
    let stdinCredentials: Bool
    init(_ arguments: [String]) throws {
        guard let package = arguments.first, !package.hasPrefix("-") else { throw SetupError.message("Supply the path to Orbit.pkg") }
        var username: String?, stdinCredentials = false
        var i = 1
        while i < arguments.count {
            if arguments[i] == "--user", username == nil, i + 1 < arguments.count {
                username = arguments[i + 1]; i += 2
            } else if arguments[i] == "--credentials-stdin", !stdinCredentials {
                stdinCredentials = true; i += 1
            } else { throw SetupError.message("Use --install-cli Orbit.pkg --user TARGET_USER [--credentials-stdin]") }
        }
        guard let username, username.range(of: #"\A[A-Za-z_][A-Za-z0-9_.-]{0,254}\z"#, options: .regularExpression) != nil else { throw SetupError.message("Supply --user with the Mac account whose usage should be tracked") }
        self.package = package; self.username = username; self.stdinCredentials = stdinCredentials
    }
}

// Restore the SSH terminal before exiting on interruption of a hidden prompt.
private var promptDescriptor: Int32 = -1
private var promptAttributes = termios()
func restorePromptOnSignal(_ value: Int32) {
    if promptDescriptor >= 0 { _ = tcsetattr(promptDescriptor, TCSANOW, &promptAttributes) }
    _exit(128 + value)
}

func terminalPrompt(_ label: String, secret: Bool = false) throws -> String {
    var terminal = fopen("/dev/tty", "r+")
    if terminal == nil && isatty(STDIN_FILENO) != 0 {
        // Some SSH/restricted sessions supply a terminal FD but deny reopening /dev/tty.
        let duplicate = dup(STDIN_FILENO)
        if duplicate >= 0 {
            terminal = fdopen(duplicate, "r+")
            if terminal == nil { close(duplicate) }
        }
    }
    guard let tty = terminal else { throw SetupError.message("No terminal. Supply --credentials-stdin with a JSON object.") }
    defer { fclose(tty) }
    let descriptor = fileno(tty)
    var previous = termios()
    let handledSignals: [Int32] = [SIGINT, SIGTERM, SIGHUP, SIGQUIT]
    var originalHandlers: [sig_t?] = []
    if secret {
        guard tcgetattr(descriptor, &previous) == 0 else { throw SetupError.message("Cannot read terminal settings") }
        promptAttributes = previous; promptDescriptor = descriptor
        for value in handledSignals { originalHandlers.append(signal(value, restorePromptOnSignal)) }
    }
    defer {
        if secret {
            _ = tcsetattr(descriptor, TCSANOW, &previous)
            promptDescriptor = -1
            for (index, value) in handledSignals.enumerated() { _ = signal(value, originalHandlers[index]) }
            fputs("\n", tty); fflush(tty)
        }
    }
    if secret {
        var hidden = previous; hidden.c_lflag &= ~tcflag_t(ECHO)
        guard tcsetattr(descriptor, TCSAFLUSH, &hidden) == 0 else { throw SetupError.message("Cannot hide terminal input") }
    }
    fputs(label + ": ", tty); fflush(tty)
    var bytes: [UInt8] = []
    while true {
        let value = fgetc(tty)
        if value == EOF { throw SetupError.message("Terminal input ended; installation cancelled") }
        if value == 10 { break }
        guard bytes.count < 8192 else { throw SetupError.message("Input too long") }
        bytes.append(UInt8(value))
    }
    guard let text = String(bytes: bytes, encoding: .utf8), !text.isEmpty else { throw SetupError.message("A value is required") }
    return text
}

func cliCredentials(saved: [String: String], user: [String: String], supplied: [String: String], prompt: (String, Bool) throws -> String) throws -> [String: String] {
    guard Set(supplied.keys).isSubset(of: ["serverURL", "deviceToken", "activityToken", "browserToken", "extensionID"]) else { throw SetupError.message("Unknown credential fields") }
    let server = try origin(supplied["serverURL"] ?? saved["serverURL"] ?? "https://orbit.side-forge.com")
    if let previous = saved["serverURL"], try origin(previous) != server { throw SetupError.message("Review existing cached policy before switching servers") }
    var fields: [String: String] = ["serverURL":server]
    for (key, label, secret) in [("deviceToken", "VPS DEVICE token", true), ("activityToken", "VPS ACTIVITY token", true), ("browserToken", "VPS BROWSER token", true), ("extensionID", "Published Chrome extension ID", false)] {
        let existing = key == "deviceToken" ? saved[key] : user[key]
        if let value = supplied[key] { fields[key] = value }
        else if let existing, key == "extensionID" || validToken(existing) { fields[key] = existing }
        else { fields[key] = try prompt(label, secret) }
    }
    let credentials = Credentials(serverURL:server, deviceToken:fields["deviceToken"]!, activityToken:fields["activityToken"]!)
    try credentials.validate()
    guard fields["browserToken"] != credentials.deviceToken, fields["browserToken"] != credentials.activityToken else { throw SetupError.message("Use distinct DEVICE, ACTIVITY and BROWSER tokens") }
    _ = try chromeProfile(extensionID: fields["extensionID"]!, serverURL:server, browserToken:fields["browserToken"]!)
    return fields
}

func stageCLIAssets(package: URL, executable: URL, in directory: URL) throws -> (package: URL, helper: URL) {
    let fm = FileManager.default
    // Remain private through validation and ownership/ACL normalization.
    // installCLI runs as root; tests can exercise the same staging under their own UID.
    try fm.createDirectory(at:directory, withIntermediateDirectories:false, attributes:[.posixPermissions:0o700])
    let staged = try stagePackage(package, in:directory)
    try fm.setAttributes([.ownerAccountID:getuid(), .groupOwnerAccountID:getgid(), .posixPermissions:0o600], ofItemAtPath:staged.path)
    let helper = directory.appendingPathComponent("OrbitSetup")
    let executable = executable.standardizedFileURL.resolvingSymlinksInPath()
    guard try executable.resourceValues(forKeys:[.isRegularFileKey]).isRegularFile == true else { throw SetupError.message("Installer helper must be a regular executable file") }
    try fm.copyItem(at:executable, to:helper)
    try fm.setAttributes([.ownerAccountID:getuid(), .groupOwnerAccountID:getgid(), .posixPermissions:0o755], ofItemAtPath:helper.path)
    // A copied ACL must not grant the source owner write access after chown.
    try run("/bin/chmod", ["-N", staged.path, helper.path])
    try fm.setAttributes([.posixPermissions:0o711], ofItemAtPath:directory.path)
    return (staged, helper)
}

func installationTransaction(prepare: () throws -> Void, install: () throws -> Void, configure: () throws -> Void, restore: () throws -> Void) throws {
    // Preparation can fail on an unrecoverable old journal; do not restart that updater.
    try prepare()
    do {
        try install()
        try configure()
    } catch {
        let original = error
        do { try restore() }
        catch { throw SetupError.message("Installation failed (\(original)); updater recovery also failed (\(error)). Review services before retrying.") }
        throw original
    }
}

func installCLI(_ options: CLIOptions) throws {
    guard getuid() == 0 else { throw SetupError.message("Run the terminal installer with sudo") }
    let installLock = try SSHInstallerLock()
    defer { withExtendedLifetime(installLock) {} }
    guard let account = getpwnam(options.username) else { throw SetupError.message("The selected Mac account does not exist") }
    try validateTargetAccount(uid:account.pointee.pw_uid, home:String(cString:account.pointee.pw_dir))
    let saved = try savedDevice()
    let supplied: [String: String]
    if options.stdinCredentials {
        guard let fields = try JSONSerialization.jsonObject(with: readInputData()) as? [String: String] else { throw SetupError.message("Supply a JSON object of credential strings") }
        supplied = fields
    } else { supplied = [:] }
    let server = try origin(supplied["serverURL"] ?? saved["serverURL"] ?? "https://orbit.side-forge.com")
    let fm = FileManager.default
    let directory = URL(fileURLWithPath:"/private/tmp").appendingPathComponent("orbit-cli-" + UUID().uuidString)
    defer { try? fm.removeItem(at:directory) }
    guard let executable = Bundle.main.executableURL else { throw SetupError.message("Cannot locate the running installer helper") }
    let assets = try stageCLIAssets(package:URL(fileURLWithPath:options.package), executable:executable, in:directory)
    let staged = assets.package, helper = assets.helper
    let output = try run("/usr/bin/sudo", ["-n", "-H", "-u", options.username, helper.path, "--saved-user-settings", server], capture:true)
    guard let user = try JSONSerialization.jsonObject(with:Data(output.utf8)) as? [String: String] else { throw SetupError.message("Cannot read target user's saved settings") }
    let fields = try cliCredentials(saved:saved, user:user, supplied:supplied) { label, secret in
        if options.stdinCredentials { throw SetupError.message("Missing credential field: " + label) }
        return try terminalPrompt(label, secret:secret)
    }
    // Validate before replacing binaries or stopping any existing service.
    try checkExistingConfiguration(settings:URL(fileURLWithPath:"/Library/Application Support/Orbit/settings.json"), cache:URL(fileURLWithPath:"/Library/Application Support/Orbit/policy.json"), serverURL:server)
    let data = try JSONSerialization.data(withJSONObject:fields)
    guard data.count <= 8192 else { throw SetupError.message("Credential input too large") }
    let updaterService = "system/com.side-forge.orbit.updater"
    let resumeUpdater = (try? run("/bin/launchctl", ["print", updaterService], capture:true)) != nil
    try installationTransaction(prepare:{ try prepareInstall() }, install:{
        try run("/usr/sbin/installer", ["-pkg", staged.path, "-target", "/"])
    }, configure:{
        try run("/usr/local/libexec/orbit-setup", ["--configure-headless", options.username], input:data)
    }, restore:{
        if resumeUpdater && (try? run("/bin/launchctl", ["print", updaterService], capture:true)) == nil { try startUpdater() }
    })
    print("Orbit installation completed without graphical prompts for " + options.username + ".")
    print("Chrome: existing approved policy is preserved. A generated profile is in the target user's Library/Application Support/Orbit/Orbit-Chrome.mobileconfig. First-time activation requires manual approval or MDM; it was not activated by this SSH install.")
    print("Check the web dashboard for blocker and tracker status. SSH tunnel provisioning is separate and remains off by default.")
}

func install(_ package: String) throws {
    guard getuid() >= 501, let user = getpwuid(getuid()) else {
        throw SetupError.message("Run Install Orbit.command from the target user's desktop, without sudo")
    }
    let username = String(cString: user.pointee.pw_name)
    let home = String(cString: user.pointee.pw_dir)
    try validateTargetAccount(uid:getuid(), home:home)
    try validateUserHome(home)
    let console = try run("/usr/bin/stat", ["-f", "%Su", "/dev/console"], capture: true)
    guard console == username else { throw SetupError.message("Log into the account whose app usage should be tracked") }
    guard FileManager.default.fileExists(atPath: package) else { throw SetupError.message("Orbit.pkg is missing; extract the entire download first") }
    // Avoid Downloads/Desktop privacy restrictions when the elevated Installer
    // reads the package. Keep the package and credentials private until cleanup.
    let directory = URL(fileURLWithPath: "/private/tmp", isDirectory: true).appendingPathComponent("orbit-setup-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: directory) }
    let stagedPackage = try stagePackage(URL(fileURLWithPath: package), in: directory)
    func prompt(_ label: String) throws -> String {
        try run("/usr/bin/osascript", ["-e", "text returned of (display dialog \"\(label)\" default answer \"\" with hidden answer buttons {\"Cancel\", \"Continue\"} default button \"Continue\" with title \"Orbit setup\")"], capture: true)
    }
    // The elevated probe returns only server metadata, never the DEVICE token.
    // Use this bundle's staged helper so upgrades from old versions work too.
    let helper = directory.appendingPathComponent("OrbitSetup")
    try FileManager.default.copyItem(at: URL(fileURLWithPath: CommandLine.arguments[0]).standardizedFileURL, to: helper)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: helper.path)
    let script = "on run argv\ndo shell script (item 1 of argv) with administrator privileges\nend run"
    let metadataJSON = try run("/usr/bin/osascript", ["-e", script, shellQuote(helper.path) + " --saved-device-info"], capture: true)
    guard let metadata = try JSONSerialization.jsonObject(with: Data(metadataJSON.utf8)) as? [String: String],
          let serverURL = metadata["serverURL"] else { throw SetupError.message("Cannot read saved installation metadata") }
    let reuseDevice = metadata["reuseDevice"] == "true"
    let saved = savedUserSettings(home: home, serverURL: serverURL)
    let device = reuseDevice ? "" : try prompt("Enter the VPS DEVICE token (not the admin token)")
    let activity = try saved["activityToken"] ?? prompt("Enter the VPS ACTIVITY token")
    let extensionID = try saved["extensionID"] ?? prompt("Enter the published Orbit Chrome Web Store extension ID (32 letters)")
    let browserToken = try saved["browserToken"] ?? prompt("Enter the distinct read-only VPS BROWSER token")
    guard validToken(activity), reuseDevice || validToken(device), browserToken != activity,
          reuseDevice || browserToken != device else { throw SetupError.message("Invalid or shared credentials") }
    let profile = try chromeProfile(extensionID: extensionID, serverURL: serverURL, browserToken: browserToken)
    let file = directory.appendingPathComponent("credentials.json")
    try privateJSON(["serverURL": serverURL, "deviceToken": device, "activityToken": activity, "browserToken": browserToken], at: file.path)
    let configureFlag = reuseDevice ? " --configure-reusing " : " --configure "
    let command = shellQuote(helper.path) + " --prepare-install && /usr/sbin/installer -pkg " + shellQuote(stagedPackage.path) + " -target / && /usr/local/libexec/orbit-setup" + configureFlag + shellQuote(username) + " < " + shellQuote(file.path)
    // Pass the command as argv, not interpolated AppleScript. macOS requests
    // administrator credentials even when the console user is a standard user.
    try run("/usr/bin/osascript", ["-e", script, command])
    let profileURL = URL(fileURLWithPath: home)
        .appendingPathComponent("Library/Application Support/Orbit/Orbit-Chrome.mobileconfig")
    try profile.write(to: profileURL, options: .atomic)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: profileURL.path)
    try run("/usr/bin/open", [profileURL.path])
    let message = "Chrome protection needs approval. In System Settings > General > Device Management, install Orbit Chrome Browser Policy using administrator credentials. Then restart Chrome and test a blocked site. Guest and Incognito will be disabled. Until approved, website blocking is not active."
    try run("/usr/bin/osascript", ["-e", "on run argv\ndisplay dialog (item 1 of argv) buttons {\"Open Settings\"} default button \"Open Settings\" with title \"Finish Chrome setup\"\nend run", message])
    try run("/usr/bin/open", ["x-apple.systempreferences:com.apple.Profiles-Settings.extension"])
    print("CHROME SETUP PENDING: Approve Orbit Chrome Browser Policy in System Settings > General > Device Management using administrator credentials. Restart Chrome, verify chrome://policy, and test a blocked site in a new profile. Guest and Incognito will be disabled after approval. The extension must already be published in the Chrome Web Store.")
    print("Orbit services installed for \(username). Confirm both connect in the dashboard.")
    try run("/usr/bin/open", [serverURL])
}

umask(0o077)
do {
    let args = CommandLine.arguments
    if args.count >= 2 && args[1] == "--install-cli" { try installCLI(CLIOptions(Array(args.dropFirst(2)))) }
    else if args.count == 3 && args[1] == "--saved-user-settings" {
        guard getuid() >= 501, let user = getpwuid(getuid()) else { throw SetupError.message("Run saved user lookup as the target user") }
        let home = String(cString:user.pointee.pw_dir)
        try validateTargetAccount(uid:getuid(), home:home)
        try validateUserHome(home)
        let result = savedUserSettings(home:home, serverURL:args[2])
        FileHandle.standardOutput.write(try JSONSerialization.data(withJSONObject:result))
    }
    else if args.count == 3 && args[1] == "--configure-headless" { try configure(args[2], headless:true) }
    else if args.count == 2 && args[1] == "--monitor-user-headless" { try monitorSetup(deferIfLoggedOut:true) }
    else if args.count == 3 && args[1] == "--install" { try install(args[2]) }
    else if args.count == 2 && args[1] == "--prepare-install" { try prepareInstall() }
    else if args.count == 2 && args[1] == "--saved-device-info" {
        let metadata = try deviceMetadata(savedDevice())
        FileHandle.standardOutput.write(try JSONSerialization.data(withJSONObject: metadata))
    }
    else if args.count == 3 && args[1] == "--configure-reusing" { try configure(args[2], reuseDevice: true) }
    else if args.count == 3 && args[1] == "--configure" { try configure(args[2]) }
    else if args.count == 2 && args[1] == "--monitor-user" { try monitorSetup() }
    else if args.count == 2 && args[1] == "--check-monitor-input" { _ = try readMonitorInput(); print("Monitor credentials valid") }
    else if args.count == 3 && args[1] == "--check-chrome-profile" {
        let values = try JSONSerialization.jsonObject(with: readInputData()) as? [String: String] ?? [:]
        FileHandle.standardOutput.write(try chromeProfile(extensionID: args[2], serverURL: values["serverURL"] ?? "", browserToken: values["browserToken"] ?? ""))
    }
    else if args.count == 2 && args[1] == "--check-input" { _ = try readInput(); print("Credentials valid") }
    else { throw SetupError.message("Use Install Orbit.command from the downloaded bundle") }
} catch SetupError.message(let message) {
    fputs("Orbit setup: \(message)\n", stderr)
    exit(1)
} catch {
    fputs("Orbit setup failed: \(error)\n", stderr)
    exit(1)
}
