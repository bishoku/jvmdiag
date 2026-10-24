import java.lang.management.ManagementFactory;
import java.nio.file.Path;
import java.nio.file.Files;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import com.sun.management.HotSpotDiagnosticMXBean;
import jdk.jfr.Configuration;
import jdk.jfr.Recording;

/** Generates artifacts in its own synthetic JVM; never attaches to an application. */
public class GenerateDiagnostics {
    static final List<Object> keep = new ArrayList<>();
    static volatile long checksum;
    static final Object monitor = new Object();
    public static void main(String[] args) throws Exception {
        Path dir = Path.of(args[0]);
        CountDownLatch held = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        Thread owner = new Thread(() -> {
            synchronized (monitor) {
                held.countDown();
                try { release.await(); } catch (InterruptedException e) { throw new RuntimeException(e); }
            }
        }, "fixture-lock-owner");
        owner.setDaemon(true); owner.start(); held.await();
        Thread blocked = new Thread(() -> { synchronized (monitor) { checksum++; } }, "fixture-blocked");
        blocked.setDaemon(true); blocked.start();
        long deadline = System.nanoTime() + 5_000_000_000L;
        while (blocked.getState() != Thread.State.BLOCKED) {
            if (System.nanoTime() > deadline) throw new IllegalStateException("fixture thread did not block");
            Thread.yield();
        }
        try (Recording recording = new Recording(Configuration.getConfiguration("profile"))) {
            recording.start();
            for (int i = 0; i < 10; i++) keep.add("jvmdiag-fixture-array-content-2026".getBytes(StandardCharsets.UTF_8));
            for (int i = 0; i < 5; i++) keep.add("fixture-character-payload".toCharArray());
            for (int round = 0; round < 4; round++) {
                for (int i = 0; i < 200_000; i++) {
                    byte[] data = new byte[128 + i % 64]; data[0] = (byte) i; checksum += data[0];
                    if (i % 50_000 == 0) keep.add(data);
                }
                System.gc();
            }
            recording.stop(); recording.dump(dir.resolve("recording.jfr"));
        }
        StringBuilder metadata = new StringBuilder();
        metadata.append(System.getProperty("java.runtime.version")).append('\n');
        metadata.append(System.getProperty("java.vendor")).append('\n');
        metadata.append(System.getProperty("os.name")).append('/').append(System.getProperty("os.arch")).append('\n');
        for (var gc : ManagementFactory.getGarbageCollectorMXBeans()) metadata.append(gc.getName()).append('\n');
        Files.writeString(dir.resolve("runtime.txt"), metadata);
        ManagementFactory.getPlatformMXBean(HotSpotDiagnosticMXBean.class).dumpHeap(dir.resolve("heap.hprof").toString(), true);
        // Optional capture mode keeps this synthetic JVM alive for matching jcmd snapshots.
        if (args.length > 1 && args[1].equals("capture")) {
            System.out.println("READY " + ProcessHandle.current().pid()); System.out.flush();
            if (System.in.read() < 0) throw new IllegalStateException("capture controller disconnected");
        }
        release.countDown();
    }
}
