package vn.edu.hcmut.co3103.identity.support;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

/** Loopback SMTP server that can hold DATA acknowledgements without replacing the real mail sender. */
public class SlowSmtpServer implements AutoCloseable {
    private final ServerSocket server;
    private final ExecutorService connections = Executors.newVirtualThreadPerTaskExecutor();
    public final CountDownLatch release = new CountDownLatch(1);
    public final AtomicInteger blocked = new AtomicInteger();
    public final List<String> messages = new CopyOnWriteArrayList<>();
    public final List<String> commands = new CopyOnWriteArrayList<>();

    public SlowSmtpServer() throws IOException {
        server = new ServerSocket(0, 50, InetAddress.ofLiteral("127.0.0.1"));
        connections.submit(() -> {
            while (!server.isClosed()) {
                try {
                    Socket peer = server.accept();
                    connections.submit(() -> serve(peer));
                } catch (IOException exception) {
                    if (!server.isClosed()) throw new UncheckedIOException(exception);
                }
            }
        });
    }

    public int port() { return server.getLocalPort(); }

    private void serve(Socket peer) {
        try (peer;
             var input = new BufferedReader(new InputStreamReader(peer.getInputStream(), StandardCharsets.UTF_8));
             var output = new PrintWriter(new OutputStreamWriter(peer.getOutputStream(), StandardCharsets.UTF_8))) {
            reply(output, "220 loopback.test ESMTP");
            String line;
            while ((line = input.readLine()) != null) {
                commands.add(line.split(" ", 2)[0]);
                if (line.startsWith("EHLO") || line.startsWith("HELO")) reply(output, "250 loopback.test");
                else if (line.equals("DATA")) {
                    reply(output, "354 End with dot");
                    StringBuilder body = new StringBuilder();
                    while ((line = input.readLine()) != null && !line.equals(".")) body.append(line).append('\n');
                    blocked.incrementAndGet();
                    try { release.await(20, TimeUnit.SECONDS); }
                    finally { blocked.decrementAndGet(); }
                    messages.add(body.toString());
                    reply(output, "250 Accepted");
                } else if (line.equals("QUIT")) {
                    reply(output, "221 Bye");
                    return;
                } else reply(output, "250 OK");
            }
        } catch (IOException ignored) {
            // A sender may time out intentionally while DATA is held.
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
        }
    }

    private void reply(PrintWriter output, String line) { output.print(line + "\r\n"); output.flush(); }

    @Override
    public void close() throws Exception {
        release.countDown();
        server.close();
        connections.shutdownNow();
        if (!connections.awaitTermination(5, TimeUnit.SECONDS)) throw new IllegalStateException("SMTP fixture did not stop");
    }
}
