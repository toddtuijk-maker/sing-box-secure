// Execute the pinned upstream importer AND outbound generator, not a Python imitation.
// This test harness never reads/writes the user's v2rayN installation or database.
using System.Reflection;
using ServiceLib.Common;
using ServiceLib.Enums;
using ServiceLib.Handler.Fmt;
using ServiceLib.Models.Configs;
using ServiceLib.Models.CoreConfigs;
using ServiceLib.Services.CoreConfig;

var lines = File.ReadAllText(args[0]);
var profiles = InnerFmt.Resolve(lines, "isolated-export-test")
    ?? throw new Exception("Importer returned no profiles");
if (profiles.Count != lines.Split('\n', StringSplitOptions.RemoveEmptyEntries).Length)
    throw new Exception("Importer silently dropped a node");
var output = new List<Outbound4Sbox>();
foreach (var node in profiles)
{
    if (!node.IsValid() || node.CoreType != ECoreType.sing_box || node.GetAllowInsecure())
        throw new Exception("Invalid node or insecure import");
    var config = new Config { CoreBasicItem = new(), HysteriaItem = new(),
        Mux4SboxItem = new(), GrpcItem = new() };
    var service = new CoreConfigSingboxService(new CoreConfigContext {
        Node = node, RunCoreType = ECoreType.sing_box, AppConfig = config });
    var method = typeof(CoreConfigSingboxService).GetMethod("BuildProxyServer", BindingFlags.Instance | BindingFlags.NonPublic)
        ?? throw new Exception("Upstream API changed; audit required");
    var outbound = (Outbound4Sbox)(method.Invoke(service, null)
        ?? throw new Exception("No outbound generated"));
    outbound.tag = node.Remarks;
    if (node.StreamSecurity == "tls" && !string.IsNullOrEmpty(node.Cert))
    {
        if (outbound.tls?.certificate?.Count is not > 0 || outbound.tls.insecure == true)
            throw new Exception("Certificate trust lost in importer/generator");
    }
    output.Add(outbound);
}
File.WriteAllText(args[1], JsonUtils.Serialize(output));
Console.WriteLine($"Upstream v2rayN 7.24.8: {output.Count} nodes imported and generated; strict TLS preserved.");
