using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace AssemblyPatcher.Patchers;

/// <summary>
/// Mutates IL opcode encodings to break byte-pattern YARA signatures.
/// Replaces short-form CIL opcodes with semantically identical long-form variants,
/// changing the binary representation without altering runtime behavior.
/// </summary>
public static class ILMutator
{
    public static int Patch(ModuleDefMD module)
    {
        int totalMutations = 0;

        foreach (var type in module.GetTypes())
        {
            foreach (var method in type.Methods)
            {
                if (method.Body?.Instructions is null)
                    continue;

                totalMutations += MutateMethod(method);
            }
        }

        return totalMutations;
    }

    private static int MutateMethod(MethodDef method)
    {
        var body = method.Body;
        var instrs = body.Instructions;
        int mutations = 0;

        for (int i = 0; i < instrs.Count; i++)
        {
            var instr = instrs[i];

            // ldloc.0..3 -> ldloc.s
            if (instr.OpCode == OpCodes.Ldloc_0)
            {
                instr.OpCode = OpCodes.Ldloc_S;
                instr.Operand = body.Variables[0];
                mutations++;
            }
            else if (instr.OpCode == OpCodes.Ldloc_1)
            {
                instr.OpCode = OpCodes.Ldloc_S;
                instr.Operand = body.Variables[1];
                mutations++;
            }
            else if (instr.OpCode == OpCodes.Ldloc_2)
            {
                instr.OpCode = OpCodes.Ldloc_S;
                instr.Operand = body.Variables[2];
                mutations++;
            }
            else if (instr.OpCode == OpCodes.Ldloc_3)
            {
                instr.OpCode = OpCodes.Ldloc_S;
                instr.Operand = body.Variables[3];
                mutations++;
            }
            // stloc.0..3 -> stloc.s
            else if (instr.OpCode == OpCodes.Stloc_0)
            {
                instr.OpCode = OpCodes.Stloc_S;
                instr.Operand = body.Variables[0];
                mutations++;
            }
            else if (instr.OpCode == OpCodes.Stloc_1)
            {
                instr.OpCode = OpCodes.Stloc_S;
                instr.Operand = body.Variables[1];
                mutations++;
            }
            else if (instr.OpCode == OpCodes.Stloc_2)
            {
                instr.OpCode = OpCodes.Stloc_S;
                instr.Operand = body.Variables[2];
                mutations++;
            }
            else if (instr.OpCode == OpCodes.Stloc_3)
            {
                instr.OpCode = OpCodes.Stloc_S;
                instr.Operand = body.Variables[3];
                mutations++;
            }
            // ldarg.0..3 -> ldarg.s
            else if (instr.OpCode == OpCodes.Ldarg_0)
            {
                instr.OpCode = OpCodes.Ldarg_S;
                instr.Operand = method.Parameters[0];
                mutations++;
            }
            else if (instr.OpCode == OpCodes.Ldarg_1 && method.Parameters.Count > 1)
            {
                instr.OpCode = OpCodes.Ldarg_S;
                instr.Operand = method.Parameters[1];
                mutations++;
            }
            else if (instr.OpCode == OpCodes.Ldarg_2 && method.Parameters.Count > 2)
            {
                instr.OpCode = OpCodes.Ldarg_S;
                instr.Operand = method.Parameters[2];
                mutations++;
            }
            else if (instr.OpCode == OpCodes.Ldarg_3 && method.Parameters.Count > 3)
            {
                instr.OpCode = OpCodes.Ldarg_S;
                instr.Operand = method.Parameters[3];
                mutations++;
            }
            // ldc.i4.0..8 -> ldc.i4.s
            else if (instr.OpCode == OpCodes.Ldc_I4_0)
            {
                instr.OpCode = OpCodes.Ldc_I4_S;
                instr.Operand = (sbyte)0;
                mutations++;
            }
            else if (instr.OpCode == OpCodes.Ldc_I4_1)
            {
                instr.OpCode = OpCodes.Ldc_I4_S;
                instr.Operand = (sbyte)1;
                mutations++;
            }
            else if (instr.OpCode == OpCodes.Ldc_I4_2)
            {
                instr.OpCode = OpCodes.Ldc_I4_S;
                instr.Operand = (sbyte)2;
                mutations++;
            }
            else if (instr.OpCode == OpCodes.Ldc_I4_3)
            {
                instr.OpCode = OpCodes.Ldc_I4_S;
                instr.Operand = (sbyte)3;
                mutations++;
            }
            else if (instr.OpCode == OpCodes.Ldc_I4_4)
            {
                instr.OpCode = OpCodes.Ldc_I4_S;
                instr.Operand = (sbyte)4;
                mutations++;
            }
            else if (instr.OpCode == OpCodes.Ldc_I4_5)
            {
                instr.OpCode = OpCodes.Ldc_I4_S;
                instr.Operand = (sbyte)5;
                mutations++;
            }
            else if (instr.OpCode == OpCodes.Ldc_I4_6)
            {
                instr.OpCode = OpCodes.Ldc_I4_S;
                instr.Operand = (sbyte)6;
                mutations++;
            }
            else if (instr.OpCode == OpCodes.Ldc_I4_7)
            {
                instr.OpCode = OpCodes.Ldc_I4_S;
                instr.Operand = (sbyte)7;
                mutations++;
            }
            else if (instr.OpCode == OpCodes.Ldc_I4_8)
            {
                instr.OpCode = OpCodes.Ldc_I4_S;
                instr.Operand = (sbyte)8;
                mutations++;
            }
            else if (instr.OpCode == OpCodes.Ldc_I4_M1)
            {
                instr.OpCode = OpCodes.Ldc_I4_S;
                instr.Operand = (sbyte)-1;
                mutations++;
            }
        }

        // Prevent dnlib from re-optimizing back to short forms
        body.KeepOldMaxStack = true;

        return mutations;
    }
}
