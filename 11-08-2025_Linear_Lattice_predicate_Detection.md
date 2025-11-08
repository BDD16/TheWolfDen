
# Lattice Linear Predicate Detection in Ghidra Using EmulatorHelper

## Premise

This Ghidra script implements a **Parallel Predicate Detector** leveraging Ghidra's `EmulatorHelper` to emulate program execution from a user-defined entry point. The script checks for the satisfaction of a symbolic and memory-based predicate of the form:

    P(i) ≡ f(i) ∧ mem[IP] == 0x42424242

Where:
- `f(i)` is a symbolic condition dependent on emulator state (e.g., `RAX == 0x42424242`),
- `mem[IP] == 0x42424242` acts as a concrete memory guard (e.g., a crash sigil or controlled instruction),
- `IP` is the instruction pointer at the current emulated state `i`.

This predicate is used to detect whether emulated paths reach semantically meaningful or crash-prone states.

---

## Theoretical Framing: Lattice Linearity

### What Is Lattice Linearity?

In distributed systems and predicate detection theory, a **lattice-linear predicate** is one where:

> If a predicate `P` is true in a global state `G`, then `P` remains true in all greater global states `G′ ≥ G` (in the lattice of system states).

Lattice Linear predicates allow efficient detection by progressing monotonically through states without backtracking.

### Why `P(i)` Is Lattice Linear

We consider the predicate:

    P(i) ≡ f(i) ∧ mem[IP] == 0x42424242

This is **lattice linear** due to the following reasoning:

1. **Monotonic Memory Condition:**
   - The memory condition `mem[IP] == 0x42424242` is evaluated at a specific instruction pointer.
   - Assuming no self modifying code or memory rollback during emulation, this value remains constant once observed.
   - Thus, this part of the predicate is monotonic.

2. **Symbolic Register Evolution:**
   - The symbolic component `f(i)` (e.g., `RAX == 0x42424242`) depends on the progression of emulator register state.
   - Emulator state evolves deterministically and monotonically under this model.
   - Once `f(i)` becomes true, subsequent states do not invalidate it (no backtracking or resets), assuming proper symbolic propagation.

4. **Conjunction Preservation:**
   - Since both `f(i)` and `mem[IP] == 0x42424242` are monotonic, their conjunction is monotonic.
   - Hence, `P(i)` holds for all future (greater) states once it becomes true.

Therefore, **`P(i)` is lattice linear**.

---

## Crash Predicate Detection: Practical Implications

The script is designed to detect predicate `P(i)` through emulation. In particular, it checks:

```java
if (hasReachedFunction(ipAddr, targetFunction) && memVal == targetOpcode) {
    println("[+] Predicate holds at address: " + ipAddr);
    printStackSnapshot(emu);
    break;
}
```

This corresponds to:

	•	hasReachedFunction(...) → ensuring control flow reached a symbolic function of interest (checkPoint)
	•	mem[IP] == 0x42424242 → detecting a known crash opcode (e.g., 0x42424242)

It is complemented by a symbolic register condition:
```java
BigInteger eaxVal = emu.readRegister(eax);
if (eaxVal != null && eaxVal.equals(BigInteger.valueOf(targetOpcode))) {
    println("[~] Symbolic condition hint: RAX == 0x42424242");
}
```

This allows detection of symbolic states that lead to memory corruption, register overwrites, or crash behavior.

## Final Summary

	•	Predicate P(i) is lattice linear under the constraints of symbolic emulation
	•	The script uses this property to detect crash like states in binary execution
	•	This enables symbolic detection of exploitable paths using Ghidra’s native infrastructure, avoiding full symbolic execution engines

# Conclusion

By modeling crash or control conditions as lattice linear predicates, this approach enables fast and monotonic detection using forward only emulation suitable for vulnerability triage, fuzzing augmentation, and binary analysis.



# Appendix
## Ghidra Script
```java
/*
 * Ghidra Java Script: Parallel Predicate Detector with EmulatorHelper (Ghidra 11.3.1 PUBLIC)
 * Predicate: P = f(i) && mem[IP] == 0x42424242
 * Symbolic Predicate Support + UI for Entry Point and Initial Register Setup
 * Author: Blake
 */

import ghidra.app.script.GhidraScript;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.lang.Register;
import ghidra.program.model.symbol.*;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.util.exception.CancelledException;

import java.math.BigInteger;
import java.util.*;

public class ParallelPredicateDetectorScript extends GhidraScript {

    private String targetFunction = "checkPoint";
    private int targetOpcode = 0x42424242;
    private FlatProgramAPI flatApi;
    private Random random = new Random();
    private int passCounter = 0;

    public void run() throws Exception {
        flatApi = new FlatProgramAPI(currentProgram, monitor);

        String entryInput = askString("Function Entry", "Enter entry point address (e.g., 0x00401000) or function name:");
        Address entry = resolveEntryPoint(entryInput);
        if (entry == null) {
            println("[!] Invalid entry point: " + entryInput);
            return;
        }

        String initRAX = askString("Initial RAX", "Enter initial RAX value (e.g., 0x20):");
        String initRSP = askString("Initial RSP", "Enter initial RSP value (e.g., 0x2FFF0000):");
        String initRBP = askString("Initial RBP", "Enter initial RBP value (e.g., 0x2FFF0000):");

        println("[*] Starting parallel predicate detector using EmulatorHelper (Ghidra 11.3.1)...");

        EmulatorHelper emu = new EmulatorHelper(currentProgram);
        emu.writeRegister("RAX", parseBigInt(initRAX));
        emu.writeRegister("RSP", parseBigInt(initRSP));
        emu.writeRegister("RBP", parseBigInt(initRBP));
        emu.writeRegister(emu.getPCRegister(), entry.getOffset());

        Address currentAddr = entry;
        while (currentAddr != null && flatApi.getInstructionAt(currentAddr) != null) {
            monitor.checkCanceled();
            passCounter++;

            if (passCounter % 100 == 0) {
                println("[!] Pass " + passCounter + " — running emulation");
                printStackSnapshot(emu);
            }
            if (passCounter % 1000 == 0) {
                println("[!] Major checkpoint at pass " + passCounter + " — reseeding RNG");
                random.setSeed(System.currentTimeMillis());
                printStackSnapshot(emu);
            }

            BigInteger ipValue = emu.readRegister(emu.getPCRegister());
            if (ipValue == null) break;

            Address ipAddr = flatApi.toAddr(ipValue.longValue());
            Instruction instr = flatApi.getInstructionAt(ipAddr);
            if (instr != null) {
                println("[INSN] " + instr);
                printRegisterState(emu, Arrays.asList("RAX", "RSP", "RBP"));
            }

            int memVal = readDword(emu, ipAddr);

            if (hasReachedFunction(ipAddr, targetFunction) && memVal == targetOpcode) {
                println("[+] Predicate holds at address: " + ipAddr);
                printStackSnapshot(emu);
                break;
            }

            checkSymbolicConditions(emu, ipAddr);

            boolean success = emu.step(monitor);
            if (!success) {
                println("[!] Emulation step failed: " + emu.getLastError());
                break;
            }

            currentAddr = emu.getExecutionAddress();
        }
        emu.dispose();

        println("[*] Predicate detection complete.");
    }

    private BigInteger parseBigInt(String input) {
        if (input.startsWith("0x")) {
            return new BigInteger(input.substring(2), 16);
        }
        return new BigInteger(input);
    }

    private Address resolveEntryPoint(String input) {
        try {
            if (input.startsWith("0x")) {
                return flatApi.toAddr(Long.parseLong(input.substring(2), 16));
            } else {
                SymbolTable symbolTable = currentProgram.getSymbolTable();
                SymbolIterator symbols = symbolTable.getSymbols(input);
                while (symbols.hasNext()) {
                    Symbol sym = symbols.next();
                    if (sym.getName().equals(input)) {
                        return sym.getAddress();
                    }
                }
            }
        } catch (Exception e) {
            println("[!] Error resolving entry point: " + e.getMessage());
        }
        return null;
    }

    private int readDword(EmulatorHelper emu, Address addr) {
        try {
            byte[] bytes = emu.readMemory(addr, 4);
            return ((bytes[3] & 0xff) << 24) |
                   ((bytes[2] & 0xff) << 16) |
                   ((bytes[1] & 0xff) << 8)  |
                   (bytes[0] & 0xff);
        } catch (Exception e) {
            return 0;
        }
    }

    private boolean hasReachedFunction(Address addr, String targetFunction) {
        Function func = flatApi.getFunctionContaining(addr);
        return func != null && func.getName().equals(targetFunction);
    }

    private void checkSymbolicConditions(EmulatorHelper emu, Address ipAddr) {
        try {
            Register eax = currentProgram.getRegister("RAX");
            BigInteger eaxVal = emu.readRegister(eax);
            if (eaxVal != null && eaxVal.equals(BigInteger.valueOf(targetOpcode))) {
                println("[~] Symbolic condition hint: RAX == 0x" + Integer.toHexString(targetOpcode) + " at " + ipAddr);
            }
        } catch (Exception e) {
            println("[!] Symbolic check failed: " + e.getMessage());
        }
    }

    private void printRegisterState(EmulatorHelper emu, List<String> regNames) {
        for (String reg : regNames) {
            try {
                BigInteger val = emu.readRegister(reg);
                println("    " + reg + " = 0x" + (val != null ? val.toString(16) : "null"));
            } catch (Exception e) {
                println("    " + reg + " = [error reading]");
            }
        }
    }

    private void printStackSnapshot(EmulatorHelper emu) {
        Register spReg = currentProgram.getCompilerSpec().getStackPointer();
        if (spReg == null) {
            println("[!] Stack pointer register not found.");
            return;
        }
        try {
            BigInteger spVal = emu.readRegister(spReg.getName());
            if (spVal == null) {
                println("[!] Could not read SP.");
                return;
            }
            Address spAddr = flatApi.toAddr(spVal.longValue());
            println("[*] Stack snapshot (SP = " + spAddr + "):");
            for (int i = 0; i < 32; i++) {
                Address addr = spAddr.add(i * 4);
                int val = readDword(emu, addr);
                println("    " + addr + ": 0x" + Integer.toHexString(val));
            }
        } catch (Exception e) {
            println("[!] Error reading stack snapshot: " + e.getMessage());
        }
    }
}
```
