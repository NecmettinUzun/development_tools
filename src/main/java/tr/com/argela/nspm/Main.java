package tr.com.argela.nspm;

import java.io.IOException;
import java.util.concurrent.CountDownLatch;

public class Main {
    public static void main(String[] args) throws IOException, InterruptedException {
        int port = resolvePort(args);
        DevToolServer server = DevToolServer.start(port);

        Runtime.getRuntime().addShutdownHook(new Thread(() -> server.stop(0)));
        System.out.printf("Dev Tool is running at http://localhost:%d/%n", server.port());

        new CountDownLatch(1).await();
    }

    private static int resolvePort(String[] args) {
        if (args.length > 0 && !args[0].isBlank()) {
            return parsePort(args[0]);
        }

        String configuredPort = System.getenv("DEV_TOOL_PORT");
        if (configuredPort != null && !configuredPort.isBlank()) {
            return parsePort(configuredPort);
        }

        return 8080;
    }

    private static int parsePort(String value) {
        int port = Integer.parseInt(value);
        if (port < 0 || port > 65535) {
            throw new IllegalArgumentException("Port must be between 0 and 65535.");
        }
        return port;
    }
}
