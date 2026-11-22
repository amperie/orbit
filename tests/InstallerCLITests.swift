let server = "https://orbit.side-forge.com"
let stored = ["serverURL":server, "deviceToken":String(repeating:"d",count:40)]
let userSettings = ["activityToken":String(repeating:"a",count:40), "browserToken":String(repeating:"b",count:40), "extensionID":String(repeating:"a",count:32)]
let options = try CLIOptions(["/a path/Orbit.pkg", "--user", "daughter", "--credentials-stdin"])
assert(options.username == "daughter" && options.stdinCredentials && options.package == "/a path/Orbit.pkg")
for args in [[String](), ["p"], ["p","--user","-root"], ["p","--user","a;sh"], ["p","--user","daughter","--user","other"], ["p","--user","daughter","--unknown"], ["p","--user","daughter","--credentials-stdin","--credentials-stdin"]] {
    do { _ = try CLIOptions(args); fatalError("Accepted invalid arguments") } catch {}
}
let reused = try cliCredentials(saved:stored, user:userSettings, supplied:[:]) { _,_ in fatalError("Prompted despite saved settings") }
assert(reused["deviceToken"] == stored["deviceToken"])
assert(reused["activityToken"] == userSettings["activityToken"])
let replaced = try cliCredentials(saved:stored, user:userSettings, supplied:["activityToken":String(repeating:"n",count:40)]) { _,_ in fatalError("Unexpected prompt") }
assert(replaced["activityToken"] == String(repeating:"n",count:40))
var asked: [String] = []
_ = try cliCredentials(saved:stored, user:["extensionID":userSettings["extensionID"]!], supplied:[:]) { label,secret in
    asked.append(label); assert(secret)
    return String(repeating:label.contains("ACTIVITY") ? "a" : "b",count:40)
}
assert(asked == ["VPS ACTIVITY token", "VPS BROWSER token"])
for input in [["serverURL":"https://other.example.com"], ["browserToken":stored["deviceToken"]!], ["activityToken":"short"], ["extensionID":"invalid"], ["unknown":"value"]] {
    do { _ = try cliCredentials(saved:stored, user:userSettings, supplied:input) { _,_ in fatalError("Unexpected prompt") }; fatalError("Accepted unsafe credentials") } catch {}
}
var calls: [[String]] = []
let deferred = try startMonitor(uid:501,plist:"/user/monitor.plist",deferIfLoggedOut:true) { path,args,_ in
    calls.append([path]+args); throw SetupError.message("GUI domain absent")
}
assert(!deferred && calls == [["/bin/launchctl","print","gui/501"]])
calls = []
let started = try startMonitor(uid:501,plist:"/user/monitor.plist",deferIfLoggedOut:true) { path,args,_ in
    calls.append([path]+args)
    if args == ["print","gui/501/com.side-forge.orbit.foreground"] { throw SetupError.message("No existing monitor") }
    return ""
}
assert(started)
assert(calls.map { $0[1] } == ["print","print","enable","bootstrap","kickstart"])
assert(calls.allSatisfy { $0[0] == "/bin/launchctl" })
do {
    _ = try startMonitor(uid:501,plist:"/user/monitor.plist",deferIfLoggedOut:true) { _,args,_ in
        if args[0] == "bootstrap" { throw SetupError.message("Bootstrap failed") }; return ""
    }
    fatalError("Silently accepted a real tracker startup failure")
} catch {}
print("Headless installer argument, credential, and tracker lifecycle checks passed")
// Failures must restore the updater only after preparation completed successfully.
for failedStage in ["none", "prepare", "install", "configure", "restore"] {
    var order: [String] = []
    do {
        try installationTransaction(prepare:{
            order.append("prepare")
            if failedStage == "prepare" { throw SetupError.message("prepare fixture") }
        }, install:{
            order.append("install")
            if failedStage == "install" { throw SetupError.message("install fixture") }
        }, configure:{
            order.append("configure")
            if failedStage == "configure" || failedStage == "restore" { throw SetupError.message("configure fixture") }
        }, restore:{
            order.append("restore")
            if failedStage == "restore" { throw SetupError.message("restore fixture") }
        })
        assert(failedStage == "none")
    } catch {
        assert(failedStage != "none")
        if failedStage == "restore" {
            let detail = String(describing:error)
            assert(detail.contains("configure fixture") && detail.contains("restore fixture"))
        }
    }
    let expected: [String]
    switch failedStage {
    case "prepare": expected = ["prepare"]
    case "install": expected = ["prepare","install","restore"]
    case "configure", "restore": expected = ["prepare","install","configure","restore"]
    default: expected = ["prepare","install","configure"]
    }
    assert(order == expected)
}
// Child exits and launch failures must not terminate the installer or leak pipes.
do { _ = try run("/usr/bin/true", [], input:Data(count:8193)); fatalError("Accepted oversized command input") } catch {}
_ = try? run("/usr/bin/false", [], input:Data(count:8192), capture:true)
func descriptorCount() -> Int {
    (0..<getdtablesize()).reduce(0) { $0 + (fcntl($1, F_GETFD) < 0 ? 0 : 1) }
}
let descriptorBaseline = descriptorCount()
for _ in 0..<80 {
    do { _ = try run("/usr/bin/false", [], input:Data(count:8192), capture:true); fatalError("Accepted failed child") } catch {}
    do { _ = try run("/missing-orbit-executable", [], input:Data(count:32), capture:true); fatalError("Accepted missing child") } catch {}
}
assert(descriptorCount() == descriptorBaseline)
print("Installation recovery and credential pipe checks passed")

try validateTargetAccount(uid:501, home:"/Users/daughter")
let invalidAccounts: [(uid_t, String)] = [(0,"/var/root"), (500,"/Users/service"), (UInt32.max - 1,"/Users/nobody"), (501,"/"), (501,"/var/empty"), (501,"/private/var/empty"), (501,"/Users/Shared"), (501,"/Users/daughter/../Shared"), (501,"relative/home")]
for (uid, home) in invalidAccounts {
    do { try validateTargetAccount(uid:uid, home:home); fatalError("Accepted an unusable account") } catch {}
}
let homeFixture = FileManager.default.temporaryDirectory.appendingPathComponent("orbit-home-check-" + UUID().uuidString)
try FileManager.default.createDirectory(at:homeFixture, withIntermediateDirectories:false)
try validateUserHome(homeFixture.path)
let fileFixture = homeFixture.appendingPathComponent("file")
try Data().write(to:fileFixture)
for bad in [fileFixture.path, homeFixture.appendingPathComponent("missing").path] {
    do { try validateUserHome(bad); fatalError("Accepted unavailable home directory") } catch {}
}
if getuid() != 0 {
    try FileManager.default.setAttributes([.posixPermissions:0o500], ofItemAtPath:homeFixture.path)
    do { try validateUserHome(homeFixture.path); fatalError("Accepted unwritable home") } catch {}
    try FileManager.default.setAttributes([.posixPermissions:0o700], ofItemAtPath:homeFixture.path)
}
try FileManager.default.removeItem(at:homeFixture)
print("Target account and home directory checks passed")
