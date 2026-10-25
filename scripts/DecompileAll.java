import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.decompiler.DecompileResults;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.FunctionIterator;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;

/** Decompile all non-external functions; flush incrementally for recoverable CI output. */
public class DecompileAll extends ghidra.app.script.GhidraScript {
    private static final int PER_FUNC_TIMEOUT = 45;
    private static final int MAX_FUNCS = 200000;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            throw new IllegalArgumentException("Usage: DecompileAll.java <output.c> <functions.txt>");
        }
        File outFile = new File(args[0]);
        File funcsFile = new File(args[1]);
        File outParent = outFile.getAbsoluteFile().getParentFile();
        File funcsParent = funcsFile.getAbsoluteFile().getParentFile();
        if (outParent != null) outParent.mkdirs();
        if (funcsParent != null) funcsParent.mkdirs();

        DecompInterface decomp = new DecompInterface();
        boolean opened = decomp.openProgram(currentProgram);
        println("decomp.openProgram = " + opened);
        if (!opened) {
            decomp.dispose();
            throw new RuntimeException("Native decompiler failed to load; check runner architecture.");
        }
        ConsoleTaskMonitor monitor = new ConsoleTaskMonitor();
        FunctionManager fm = currentProgram.getFunctionManager();
        FunctionIterator it = fm.getFunctions(true);
        int total = 0;
        int done = 0;
        int failed = 0;
        int external = 0;

        try (PrintWriter out = new PrintWriter(new OutputStreamWriter(
                    new FileOutputStream(outFile), StandardCharsets.UTF_8));
             PrintWriter fl = new PrintWriter(new OutputStreamWriter(
                    new FileOutputStream(funcsFile), StandardCharsets.UTF_8))) {
            while (it.hasNext() && total < MAX_FUNCS) {
                Function f = it.next();
                total++;
                fl.println(f.getEntryPoint() + " " + f.getName());
                if (f.isExternal()) {
                    external++;
                    continue;
                }
                try {
                    DecompileResults res = decomp.decompileFunction(f, PER_FUNC_TIMEOUT, monitor);
                    DecompiledFunction df = (res == null) ? null : res.getDecompiledFunction();
                    if (df != null) {
                        out.println("// Function: " + f.getName() + " @ " + f.getEntryPoint());
                        out.println(df.getC());
                        out.println();
                        done++;
                    } else {
                        failed++;
                    }
                } catch (Throwable t) {
                    failed++;
                    out.println("// Function: " + f.getName() + " @ " + f.getEntryPoint()
                            + " [DECOMPILE FAILED: " + t.getClass().getName() + "]");
                }
                if (total % 100 == 0) {
                    out.flush();
                    fl.flush();
                    println("progress: " + done + "/" + total + " (failed " + failed + ")");
                }
            }
            out.flush();
            fl.flush();
        } finally {
            decomp.dispose();
        }
        println("TOTAL functions seen: " + total);
        println("Decompiled OK: " + done + " | Failed: " + failed + " | External: " + external);
        println("Wrote " + outFile.getAbsolutePath() + " (" + outFile.length() + " bytes)");
        println("Wrote " + funcsFile.getAbsolutePath() + " (" + funcsFile.length() + " bytes)");
        if (total == 0 || done == 0 || outFile.length() == 0) {
            throw new RuntimeException("No decompiled output; see counters and openProgram state.");
        }
    }
}
