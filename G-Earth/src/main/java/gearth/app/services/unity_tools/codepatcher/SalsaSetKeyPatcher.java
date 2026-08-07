package gearth.app.services.unity_tools.codepatcher;

import wasm.disassembly.instructions.Instr;
import wasm.disassembly.instructions.InstrType;
import wasm.disassembly.instructions.control.BlockInstr;
import wasm.disassembly.instructions.control.IfElseInstr;
import wasm.disassembly.instructions.memory.MemInstr;
import wasm.disassembly.instructions.variable.LocalVariableInstr;
import wasm.disassembly.modules.sections.code.Func;
import wasm.disassembly.modules.sections.code.Locals;
import wasm.disassembly.types.FuncType;
import wasm.disassembly.types.ResultType;
import wasm.disassembly.types.ValType;
import wasm.misc.StreamReplacement;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Namespace    Org.BouncyCastle.Crypto.Engines
 * Class        Salsa20Engine
 * Method       SetKey(byte[] keyBytes, byte[] ivBytes)
 * Locate function with StringLiteral "requires 128 bit or 256 bit key".
 */
public class SalsaSetKeyPatcher extends StreamReplacement {

    @Override
    public FuncType getFuncType() {
        return new FuncType(
                new ResultType(Arrays.asList(ValType.I32, ValType.I32, ValType.I32, ValType.I32)),
                new ResultType(Collections.emptyList()));
    }

    @Override
    public ReplacementType getReplacementType() {
        return ReplacementType.HOOK;
    }

    @Override
    public String getImportName() {
        return "g_chacha_setkey";
    }

    @Override
    public String getExportName() {
        return null;
    }

    @Override
    public boolean codeMatches(int id, Func code) {
        return matchesLegacyLayout(code) || matchesCurrentLayout(code);
    }

    private static boolean matchesLegacyLayout(Func code) {
        if (!code.getLocalss().isEmpty()) return false;

        final List<Instr> expression = code.getExpression().getInstructions();
        final List<InstrType> expectedExpr = Arrays.asList(
                InstrType.LOCAL_GET,
                InstrType.IF,
                InstrType.LOCAL_GET,
                InstrType.I32_CONST,
                InstrType.LOCAL_GET,
                InstrType.I32_LOAD,
                InstrType.I32_CONST,
                InstrType.I32_CONST,
                InstrType.I32_CONST,
                InstrType.CALL);

        return codeEquals(expression, expectedExpr);
    }

    private static boolean matchesCurrentLayout(Func code) {
        if (!code.getLocalss().equals(Collections.singletonList(new Locals(1, ValType.I32)))) return false;

        final List<Instr> expression = code.getExpression().getInstructions();
        final List<InstrType> expectedExpr = Arrays.asList(
                InstrType.LOCAL_GET,
                InstrType.IF,
                InstrType.LOCAL_GET,
                InstrType.I32_LOAD,
                InstrType.LOCAL_TEE,
                InstrType.LOCAL_GET,
                InstrType.I32_LOAD,
                InstrType.I32_STORE,
                InstrType.LOCAL_GET,
                InstrType.LOCAL_GET,
                InstrType.I32_LOAD,
                InstrType.I32_STORE);

        if (!codeEquals(expression, expectedExpr)) return false;
        if (localIndex(expression.get(0)) != 1) return false;
        if (localIndex(expression.get(2)) != 0 || memoryOffset(expression.get(3)) != 16) return false;
        if (localIndex(expression.get(4)) != 1 || localIndex(expression.get(5)) != 2) return false;
        if (memoryOffset(expression.get(6)) != 16 || memoryOffset(expression.get(7)) != 72) return false;
        if (localIndex(expression.get(8)) != 1 || localIndex(expression.get(9)) != 2) return false;
        if (memoryOffset(expression.get(10)) != 20 || memoryOffset(expression.get(11)) != 76) return false;

        final IfElseInstr keyBranch = (IfElseInstr) expression.get(1);
        final List<Integer> storeOffsets = new ArrayList<>();
        collectStoreOffsets(keyBranch.getIfInstructions(), storeOffsets);

        return keyBranch.getElseInstructions() == null
                && storeOffsets.equals(Arrays.asList(32, 36, 40, 44, 48, 52, 56, 60));
    }

    private static int localIndex(Instr instruction) {
        return Math.toIntExact(((LocalVariableInstr) instruction).getLocalIdx().getX());
    }

    private static long memoryOffset(Instr instruction) {
        return ((MemInstr) instruction).getMemArg().getOffset();
    }

    private static void collectStoreOffsets(List<Instr> instructions, List<Integer> offsets) {
        if (instructions == null) return;

        for (Instr instruction : instructions) {
            if (instruction.getInstrType() == InstrType.I32_STORE) {
                offsets.add(Math.toIntExact(memoryOffset(instruction)));
            }

            if (instruction instanceof IfElseInstr branch) {
                collectStoreOffsets(branch.getIfInstructions(), offsets);
                collectStoreOffsets(branch.getElseInstructions(), offsets);
            } else if (instruction instanceof BlockInstr block) {
                collectStoreOffsets(block.getBlockInstructions(), offsets);
            }
        }
    }
}
