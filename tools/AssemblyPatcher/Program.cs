using dnlib.DotNet;
using dnlib.DotNet.Writer;
using AssemblyPatcher.Patchers;

if (args.Length < 2)
{
    Console.Error.WriteLine("Usage: AssemblyPatcher <input> <output> [--randomize-guids] [--mutate-il]");
    Console.Error.WriteLine();
    Console.Error.WriteLine("If no flags are specified, both --randomize-guids and --mutate-il are applied.");
    return 1;
}

string inputPath = args[0];
string outputPath = args[1];

// Parse flags — default to both if none specified
var flags = new HashSet<string>(args.Skip(2), StringComparer.OrdinalIgnoreCase);
bool randomizeGuids = flags.Contains("--randomize-guids");
bool mutateIl = flags.Contains("--mutate-il");

// If no flags given, enable both by default
if (!randomizeGuids && !mutateIl)
{
    randomizeGuids = true;
    mutateIl = true;
}

if (!File.Exists(inputPath))
{
    Console.Error.WriteLine($"[AssemblyPatcher] Input file not found: {inputPath}");
    return 1;
}

try
{
    Console.Error.WriteLine($"[AssemblyPatcher] Loading {inputPath}...");
    var module = ModuleDefMD.Load(inputPath);
    int totalChanges = 0;

    if (randomizeGuids)
    {
        int guidChanges = GuidRandomizer.Patch(module);
        Console.Error.WriteLine($"[AssemblyPatcher] GUIDs randomized: {guidChanges} changes");
        totalChanges += guidChanges;
    }

    if (mutateIl)
    {
        int ilChanges = ILMutator.Patch(module);
        Console.Error.WriteLine($"[AssemblyPatcher] IL opcodes mutated: {ilChanges} changes");
        totalChanges += ilChanges;
    }

    // Write with options that prevent re-optimization of our mutations
    var writerOptions = new ModuleWriterOptions(module)
    {
        Logger = DummyLogger.NoThrowInstance,
    };

    module.Write(outputPath, writerOptions);

    var inputSize = new FileInfo(inputPath).Length;
    var outputSize = new FileInfo(outputPath).Length;
    Console.Error.WriteLine(
        $"[AssemblyPatcher] Done: {totalChanges} patches applied, {inputSize} -> {outputSize} bytes");
    return 0;
}
catch (Exception ex)
{
    Console.Error.WriteLine($"[AssemblyPatcher] Error: {ex.Message}");
    return 1;
}
