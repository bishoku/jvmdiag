import java.util.concurrent.CountDownLatch;
import java.util.concurrent.locks.LockSupport;
public final class Fixture {
    static final byte[][] retained = new byte[16][];
    public static void main(String[] args) throws Exception {
        Thread allocator = new Thread(() -> {
            int i = 0;
            while (true) {
                retained[i++ % retained.length] = new byte[128 * 1024];
                LockSupport.parkNanos(10_000_000L);
            }
        }, "jvmdiag-fixture-allocator");
        allocator.setDaemon(true);
        allocator.start();
        System.out.println("READY");
        new CountDownLatch(1).await();
    }
}
