// Appended to the helper's definitions by test_tunnel_helper.py; no daemon startup.
func expectInvalid(_ data: String) {
    do { let config = try JSONDecoder().decode(TunnelConfig.self, from: Data(data.utf8)); try config.validate(); fatalError("Accepted unsafe config") }
    catch {}
}
for host in ["-oProxyCommand=sh", "host;id", "host\ncommand", "", "../host"] {
    let data = try! JSONSerialization.data(withJSONObject: ["host":host,"user":"orbit-tunnel","port":22,"remotePort":22001])
    expectInvalid(String(data:data,encoding:.utf8)!)
}
let valid = TunnelConfig(host:"vps.example.com", port:22, user:"orbit-tunnel", remotePort:22001)
try! valid.validate()
let arguments = sshArguments(valid)
assert(arguments.contains("127.0.0.1:22001:127.0.0.1:2222"))
assert(arguments.contains("StrictHostKeyChecking=yes"))
assert(arguments.contains("PasswordAuthentication=no"))
assert(arguments.contains("UserKnownHostsFile=\"/Library/Application Support/OrbitTunnel/known_hosts\""))
let anchor = "2026-11-21T12:00:00Z"
assert(leaseDuration(Control(enabled:false,expiresAt:"2026-11-21T13:00:00Z",serverTimeUTC:anchor)) == 0)
assert(leaseDuration(Control(enabled:true,expiresAt:nil,serverTimeUTC:anchor)) == 0)
assert(leaseDuration(Control(enabled:true,expiresAt:"invalid",serverTimeUTC:anchor)) == 0)
assert(leaseDuration(Control(enabled:true,expiresAt:"2026-11-21T11:59:59Z",serverTimeUTC:anchor)) == 0)
assert(leaseDuration(Control(enabled:true,expiresAt:"2027-11-21T12:00:00Z",serverTimeUTC:anchor)) == 3600)
assert(leaseDuration(Control(enabled:true,expiresAt:"2026-11-21T12:00:02Z",serverTimeUTC:anchor)) == 2)
for url in ["http://vps.example.com", "https://user:password@vps.example.com", "https://vps.example.com/?secret=1"] {
    do { try DeviceSettings(serverURL:url,deviceToken:String(repeating:"x",count:40)).validate(); fatalError("Accepted unsafe server URL") } catch {}
}
let unbounded = Control(enabled:true, expiresAt:nil, serverTimeUTC:anchor, persistent:true)
assert(leaseDuration(unbounded) == 0)
let decoded = try! JSONDecoder().decode(Control.self, from: Data(#"{"enabled":true,"expiresAt":"2026-11-21T13:00:00Z","serverTimeUTC":"2026-11-21T12:00:00Z"}"#.utf8))
assert(leaseDuration(decoded) == 3600)
let supervisor = TunnelState()
let stopped = Process(); stopped.executableURL = URL(fileURLWithPath:"/bin/sleep"); stopped.arguments = ["60"]
try! supervisor.start(stopped)
assert(!supervisor.running())
supervisor.updateLease(continuousTime() + leaseDuration(decoded))
let active = Process(); active.executableURL = URL(fileURLWithPath:"/bin/sleep"); active.arguments = ["60"]
try! supervisor.start(active)
assert(supervisor.running())
supervisor.updateLease(0)
assert(!supervisor.running())
assert(!active.isRunning)
// Exercise the actual daemon watchdog while this thread is blocked, as with stalled networking.
tunnel.updateLease(continuousTime() + 0.15)
let expiring = Process(); expiring.executableURL = URL(fileURLWithPath:"/bin/sleep"); expiring.arguments = ["60"]
try! tunnel.start(expiring)
assert(tunnel.running())
Thread.sleep(forTimeInterval: 0.6)
assert(!expiring.isRunning)
assert(!tunnel.authorized())
print("Tunnel helper security and lifecycle checks passed")
