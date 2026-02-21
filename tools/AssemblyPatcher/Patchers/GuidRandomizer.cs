using dnlib.DotNet;

namespace AssemblyPatcher.Patchers;

/// <summary>
/// Replaces all GUIDs in the assembly metadata to defeat GUID-based YARA signatures.
/// Targets: MVID, EncId, EncBaseId, and all GuidAttribute values on assembly/types.
/// </summary>
public static class GuidRandomizer
{
    public static int Patch(ModuleDefMD module)
    {
        int count = 0;

        // Replace module-level GUIDs
        module.Mvid = Guid.NewGuid();
        count++;

        if (module.EncId.HasValue)
        {
            module.EncId = Guid.NewGuid();
            count++;
        }

        if (module.EncBaseId.HasValue)
        {
            module.EncBaseId = Guid.NewGuid();
            count++;
        }

        // Replace GuidAttribute on the assembly itself
        if (module.Assembly is not null)
        {
            count += ReplaceGuidAttributes(module.Assembly.CustomAttributes);
        }

        // Replace GuidAttribute on all types
        foreach (var type in module.GetTypes())
        {
            count += ReplaceGuidAttributes(type.CustomAttributes);
        }

        return count;
    }

    private static int ReplaceGuidAttributes(CustomAttributeCollection attrs)
    {
        int count = 0;
        foreach (var attr in attrs)
        {
            if (attr.AttributeType?.Name != "GuidAttribute")
                continue;
            if (attr.ConstructorArguments.Count < 1)
                continue;
            if (attr.ConstructorArguments[0].Type?.FullName != "System.String")
                continue;

            var newGuid = Guid.NewGuid().ToString();
            attr.ConstructorArguments[0] = new CAArgument(
                attr.ConstructorArguments[0].Type,
                new UTF8String(newGuid));
            count++;
        }
        return count;
    }
}
