import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.*;

public class MultiPassVxWorksFunctionAnalysisWithRefinedLogging extends GhidraScript {

    private FileWriter logWriter;

    private Map<Address, String> symbols = new HashMap<>();
    private Map<Address, String> functionNames = new HashMap<>();
    private Set<Address> potentialFunctions = new HashSet<>();
    private Map<Address, String> crossReferencedFunctions = new HashMap<>();

    @Override
    public void run() throws CancelledException {
        try {
            // Initialize logging
            initializeLog();

            log("Starting multi-pass analysis for VxWorks functions...");

            // Pass 1: Scan for symbols
            log("Pass 1: Scanning for symbols...");
            scanForSymbols();
            heuristicForDSFunctionNames();
            log("Found " + symbols.size() + " symbols.");

            // Pass 2: Extract function names
            log("Pass 2: Extracting function names from symbols and strings...");
            extractFunctionNames();
            heuristicForDSFunctionNames();
            log("Identified " + functionNames.size() + " function names.");

            // Pass 3: Scan for functions
            log("Pass 3: Scanning for potential functions...");
            scanForFunctions();
            heuristicForDSFunctionNames();
            log("Found " + potentialFunctions.size() + " potential functions.");

            // Pass 4: Cross-reference analysis
            log("Pass 4: Performing cross-reference analysis...");
            performCrossReferenceAnalysis();
            heuristicForDSFunctionNames();
            log("Identified " + crossReferencedFunctions.size() + " cross-referenced functions.");

            // Final Labeling
            log("Final Pass: Labeling functions...");
            labelFunctions();
            log("Function labeling completed.");
        } catch (IOException e) {
            println("Error initializing or writing to the log file: " + e.getMessage());
        } finally {
            // Close log writer
            closeLog();
        }
    }

    private void scanForSymbols() throws CancelledException {
        Address start = currentProgram.getMinAddress();
        Address end = currentProgram.getMaxAddress();
        Address current = start;

        while (current.compareTo(end) < 0) {
            monitor.checkCanceled();

            Address potentialAddress = extractPointer(current);
            if (potentialAddress != null && isExecutableAddress(potentialAddress)) {
                String symbolName = extractString(current.add(4));
                if (symbolName != null 
                        && symbolName.length() >= 3 // Minimum length
                        && matchesVxWorksNamingConvention(symbolName)) {
                    symbols.put(potentialAddress, symbolName);
                    try {
                        log("Symbol Found: " + symbolName + " at " + potentialAddress);
                    } catch (IOException e) {
                        println("Failed to log symbol: " + e.getMessage());
                    }
                }
            }

            current = current.add(4); // Move to the next potential entry
        }
    }

    private void heuristicForDSFunctionNames() throws CancelledException {
        try {
            log("Applying heuristic to identify 'ds' function names with addresses...");
        } catch (IOException e) {
            println("Failed to log heuristic application: " + e.getMessage());
        }

        Address start = currentProgram.getMinAddress();
        Address end = currentProgram.getMaxAddress();
        Address current = start;

        while (current.compareTo(end) < 0) {
            monitor.checkCanceled();

            String functionName = extractString(current);
            if (functionName != null 
                    && functionName.length() >= 3 // Minimum length threshold
                    && matchesVxWorksNamingConvention(functionName)) {
                
                Address potentialFunctionAddress = extractPointer(current.add(functionName.length() + 1));

                if (potentialFunctionAddress != null 
                        && isExecutableAddress(potentialFunctionAddress) 
                        && isAligned(potentialFunctionAddress)) {
                    if (!functionNames.containsKey(potentialFunctionAddress)) {
                        functionNames.put(potentialFunctionAddress, functionName);
                        try {
                            log("Identified 'ds' function: " + functionName + " at " + potentialFunctionAddress);
                        } catch (IOException e) {
                            println("Failed to log 'ds' function: " + e.getMessage());
                        }
                    }
                }
            }

            current = current.add(1); // Increment byte-by-byte
        }
    }

    private void extractFunctionNames() throws CancelledException {
        Address start = currentProgram.getMinAddress();
        Address end = currentProgram.getMaxAddress();
        Address current = start;

        while (current.compareTo(end) < 0) {
            monitor.checkCanceled();

            String potentialName = extractString(current);
            if (potentialName != null 
                    && potentialName.length() >= 3 
                    && matchesVxWorksNamingConvention(potentialName)) {
                functionNames.put(current, potentialName);
                try {
                    log("Function Name Found: " + potentialName + " at " + current);
                } catch (IOException e) {
                    println("Failed to log function name: " + e.getMessage());
                }
            }

            current = current.add(1); // Increment byte-by-byte for string scanning
        }
    }

    private void scanForFunctions() throws CancelledException {
        Address start = currentProgram.getMinAddress();
        Address end = currentProgram.getMaxAddress();

        for (Address address = start; address.compareTo(end) < 0; address = address.add(4)) {
            monitor.checkCanceled();

            if (isValidFunctionEntryPoint(address)) {
                potentialFunctions.add(address);
                try {
                    log("Potential Function Found at: " + address);
                } catch (IOException e) {
                    println("Failed to log potential function: " + e.getMessage());
                }
            }
        }
    }

    private void performCrossReferenceAnalysis() throws CancelledException {
        SymbolTable symbolTable = currentProgram.getSymbolTable();

        for (Address address : potentialFunctions) {
            monitor.checkCanceled();

            Symbol[] refs = symbolTable.getSymbols(address);
            if (refs.length > 0) {
                String functionName = functionNames.getOrDefault(address, "unknown_function");
                crossReferencedFunctions.put(address, functionName);
                try {
                    log("Cross-referenced Function: " + functionName + " at " + address);
                } catch (IOException e) {
                    println("Failed to log cross-referenced function: " + e.getMessage());
                }
            }
        }
    }

    private void labelFunctions() {
        Listing listing = currentProgram.getListing();
    
        for (Map.Entry<Address, String> entry : crossReferencedFunctions.entrySet()) {
            Address functionAddress = entry.getKey();
            String functionName = entry.getValue();
    
            try {
                Function existingFunction = listing.getFunctionAt(functionAddress);
                if (existingFunction == null) {
                    // No existing function, create a new one
                    listing.createFunction(functionName, functionAddress, null, SourceType.IMPORTED);
                    log("Created Function: " + functionName + " at " + functionAddress);
                } else {
                    // Check if the existing function's name matches VxWorks naming convention
                    String existingName = existingFunction.getName();
                    if (!matchesVxWorksNamingConvention(existingName)) {
                        // Override the existing name with the new one
                        existingFunction.setName(functionName, SourceType.IMPORTED);
                        log("Overrode Existing Function: " + existingName + " with " + functionName + " at " + functionAddress);
                    } else {
                        log("Function Already Exists with Valid Name at: " + functionAddress + " (" + existingName + ")");
                    }
                }
            } catch (IOException e) {
                println("Failed to log labeled function: " + e.getMessage());
            } catch (Exception e) {
                println("Failed to Label Function at " + functionAddress + ": " + e.getMessage());
            }
        }
    }
    

    private void initializeLog() throws IOException {
        File logDir = new File("/var/ghidra/logs/");
        if (!logDir.exists()) {
            if (!logDir.mkdirs()) {
                throw new IOException("Failed to create log directory: " + logDir.getAbsolutePath());
            }
        }

        File logFile = new File(logDir, "vxworks_analysis.log");
        logWriter = new FileWriter(logFile, true); // Append mode
        log("Log initialized at: " + logFile.getAbsolutePath());
    }

    private void log(String message) throws IOException {
        String timestampedMessage = "[" + new Date() + "] " + message;
        println(timestampedMessage); // Print to Ghidra console
        logWriter.write(timestampedMessage + "\n");
        logWriter.flush();
    }

    private void closeLog() {
        if (logWriter != null) {
            try {
                logWriter.close();
            } catch (IOException e) {
                println("Error closing the log file: " + e.getMessage());
            }
        }
    }

    private Address extractPointer(Address address) {
        try {
            long value = currentProgram.getMemory().getInt(address) & 0xFFFFFFFFL;
            return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(value);
        } catch (Exception e) {
            return null;
        }
    }

    private String extractString(Address address) {
        try {
            StringBuilder sb = new StringBuilder();
            while (true) {
                byte b = currentProgram.getMemory().getByte(address);
                if (b == 0) {
                    return sb.toString(); // Null-terminated string
                }
                if (!isPrintableChar(b)) {
                    return null; // Stop on non-printable character
                }
                sb.append((char) b);
                address = address.add(1);
            }
        } catch (Exception e) {
            return null; // Return null on any memory access failure
        }
    }

    private boolean matchesVxWorksNamingConvention(String name) {
        return name.matches("^[a-zA-Z_][a-zA-Z0-9_]*$") && (
            name.startsWith("dw") || name.startsWith("w") || name.startsWith("Get") ||
            name.startsWith("Set") || name.startsWith("Sub") || name.startsWith("Sys") ||
            name.startsWith("Dram") || name.startsWith("Mem") || name.startsWith("Type") ||
            name.startsWith("v") || name.startsWith("vx") || name.startsWith("task") ||
            name.startsWith("sem") || name.startsWith("usr") || name.startsWith("log"));
    }

    private boolean isExecutableAddress(Address address) {
        return currentProgram.getMemory().getExecuteSet().contains(address);
    }

    private boolean isValidFunctionEntryPoint(Address address) {
        try {
            byte firstByte = currentProgram.getMemory().getByte(address);
            return (firstByte == (byte) 0xE9 || firstByte == (byte) 0x55 || firstByte == (byte) 0xB5 || firstByte == (byte) 0x90);
        } catch (Exception e) {
            return false;
        }
    }

    private boolean isAligned(Address address) {
        long offset = address.getOffset();
        return (offset % 4 == 0 || offset % 8 == 0);
    }

    private boolean isPrintableChar(byte b) {
        return b >= 0x20 && b <= 0x7E;
    }
}
