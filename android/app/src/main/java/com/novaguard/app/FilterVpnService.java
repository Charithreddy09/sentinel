package com.novaguard.app;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.VpnService;
import android.os.Handler;
import android.os.Looper;
import android.os.ParcelFileDescriptor;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.Arrays;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * DNS-level filter VPN. Only DNS traffic (to the fake resolver) is routed
 * into the tunnel; blocked domains get NXDOMAIN, allowed ones are forwarded
 * to a real resolver. IPv6 is blackholed so nothing leaks around the filter.
 */
public class FilterVpnService extends VpnService {

    static final String FAKE_DNS = "10.111.222.3";
    private static final String[] REAL_DNS = {"1.1.1.1", "8.8.8.8"};
    private static final String CHANNEL = "novaguard";
    private static final int ALERT_ID = 2;
    // Canary for the self-check: a domain the filter must always block. If this
    // stops matching, the blocklist itself has failed to load.
    private static final String CANARY = "pornhub.com";

    private ParcelFileDescriptor tun;
    private volatile boolean running;
    private FileOutputStream out;
    private final Object outLock = new Object();
    private final AtomicInteger packetId = new AtomicInteger(1);
    private ExecutorService pool;
    private Blocklist blocklist;
    private NotificationManager nm;
    private Handler ui;
    private Runnable selfCheck;

    @Override
    public void onCreate() {
        super.onCreate();
        blocklist = new Blocklist(this);
        pool = Executors.newFixedThreadPool(8);
        nm = getSystemService(NotificationManager.class);
        ui = new Handler(Looper.getMainLooper());
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        createChannel();
        startForeground(1, buildNotification());
        startVpn();
        scheduleSelfCheck();
        return START_STICKY;
    }

    /**
     * Periodic self-check: prove the filter is actually catching things, not
     * merely claiming to be on. Once a minute, run a canary domain through the
     * exact same isBlocked() path a live query takes. If it stops being blocked,
     * something upstream of the tunnel broke and the app says so loudly instead
     * of showing a confident "on".
     */
    private void scheduleSelfCheck() {
        if (selfCheck != null) return;
        selfCheck = new Runnable() {
            @Override
            public void run() {
                if (!running) return;
                boolean healthy;
                try {
                    healthy = blocklist.isBlocked(CANARY);
                } catch (Exception e) {
                    healthy = false;
                }
                if (!healthy) {
                    postAlert();
                } else {
                    clearAlert();
                }
                ui.postDelayed(this, 60_000);
            }
        };
        ui.postDelayed(selfCheck, 10_000);
    }

    private void postAlert() {
        try {
            Notification n = new Notification.Builder(this, CHANNEL)
                    .setContentTitle("⚠️ Protection has stopped working")
                    .setContentText("Tap to fix — your filter is not catching content right now")
                    .setSmallIcon(android.R.drawable.stat_sys_warning)
                    .setContentIntent(PendingIntent.getActivity(this, 0,
                            new Intent(this, MainActivity.class), PendingIntent.FLAG_IMMUTABLE))
                    .setAutoCancel(false)
                    .setOngoing(true)
                    .build();
            nm.notify(ALERT_ID, n);
        } catch (Exception ignored) {
        }
    }

    private void clearAlert() {
        try {
            nm.cancel(ALERT_ID);
        } catch (Exception ignored) {
        }
    }

    @Override
    public void onDestroy() {
        running = false;
        prefs().edit().putBoolean("on", false).apply();
        try {
            if (tun != null) tun.close();
        } catch (Exception ignored) { }
        if (pool != null) pool.shutdownNow();
        super.onDestroy();
    }

    private SharedPreferences prefs() {
        return getSharedPreferences("novaguard", MODE_PRIVATE);
    }

    private void startVpn() {
        if (running) return;
        VpnService.Builder b = new VpnService.Builder()
                .setSession("NovaGuard")
                .setMtu(1500)
                .addAddress("10.111.222.2", 32)
                .addDnsServer(FAKE_DNS)
                .addRoute(FAKE_DNS, 32)
                // blackhole IPv6 so nothing bypasses the filter over v6
                .addAddress("fdfe:dcba:9876::2", 126)
                .addRoute("::", 0);
        try {
            tun = b.establish();
        } catch (Exception e) {
            tun = null;
        }
        if (tun == null) {
            // Establish failed. Do not leave a stale "on" flag behind, or the
            // screen and BootReceiver would both believe protection is running.
            prefs().edit().putBoolean("on", false).apply();
            stopSelf();
            return;
        }
        running = true;
        prefs().edit().putBoolean("on", true).apply();
        Thread worker = new Thread(this::loop, "novaguard-loop");
        worker.setPriority(Thread.MAX_PRIORITY);
        worker.start();
    }

    private void loop() {
        try (FileInputStream in = new FileInputStream(tun.getFileDescriptor())) {
            out = new FileOutputStream(tun.getFileDescriptor());
            byte[] buf = new byte[32768];
            while (running) {
                int len = in.read(buf);
                if (len <= 0) continue;
                final byte[] pkt = Arrays.copyOf(buf, len);
                pool.execute(() -> handle(pkt));
            }
        } catch (IOException ignored) {
            // tun closed — service is going down
        }
    }

    private void handle(byte[] pkt) {
        if (pkt.length < 28) return;
        if ((pkt[0] & 0xf0) != 0x40) return; // drop IPv6 / junk
        int ihl = (pkt[0] & 0x0f) * 4;
        if (pkt.length < ihl + 20) return;
        if (pkt[9] != 17) return; // UDP only
        if (pkt[16] != 10 || pkt[17] != (byte) 111 || pkt[18] != (byte) 222 || pkt[19] != 3) {
            return; // not a DNS query to the fake resolver
        }
        int srcPort = ((pkt[ihl] & 0xff) << 8) | (pkt[ihl + 1] & 0xff);
        int dstPort = ((pkt[ihl + 2] & 0xff) << 8) | (pkt[ihl + 3] & 0xff);
        if (dstPort != 53) return;
        int udpLen = ((pkt[ihl + 4] & 0xff) << 8) | (pkt[ihl + 5] & 0xff);
        int dnsStart = ihl + 8;
        int dnsLen = udpLen - 8;
        if (dnsLen < 12 || pkt.length < dnsStart + dnsLen) return;
        byte[] q = Arrays.copyOfRange(pkt, dnsStart, dnsStart + dnsLen);

        String domain = Blocklist.qname(q);
        if (domain == null) return;

        byte[] resp;
        try {
            if (blocklist.isBlocked(domain)) {
                resp = Blocklist.nxDomain(q);
            } else {
                String safe = Blocklist.safeTarget(domain);
                if (safe != null) {
                    byte[] safeQ = Blocklist.buildQuery(safe, 0x4e0b);
                    byte[] safeResp = upstream(safeQ);
                    byte[][] ips = safeResp == null ? new byte[0][] : Blocklist.parseARecords(safeResp);
                    resp = Blocklist.answerWith(q, ips);
                    if (resp == null) resp = upstream(q);
                    if (resp == null) return;
                } else {
                    resp = upstream(q);
                    if (resp == null) return;
                }
            }
        } catch (Exception e) {
            return;
        }
        writeBack(pkt, ihl, srcPort, resp);
    }

    private byte[] upstream(byte[] query) {
        for (String server : REAL_DNS) {
            DatagramSocket s = null;
            try {
                s = new DatagramSocket();
                protect(s);
                s.setSoTimeout(4000);
                s.send(new DatagramPacket(query, query.length, InetAddress.getByName(server), 53));
                byte[] rb = new byte[4096];
                DatagramPacket rp = new DatagramPacket(rb, rb.length);
                s.receive(rp);
                return Arrays.copyOf(rp.getData(), rp.getLength());
            } catch (Exception ignored) {
            } finally {
                if (s != null) s.close();
            }
        }
        return null;
    }

    private void writeBack(byte[] orig, int ihl, int srcPort, byte[] dns) {
        try {
            int total = ihl + 8 + dns.length;
            byte[] p = new byte[total];
            System.arraycopy(orig, 0, p, 0, ihl);
            p[2] = (byte) (total >> 8); p[3] = (byte) total;
            int id = packetId.incrementAndGet();
            p[4] = (byte) (id >> 8); p[5] = (byte) id;
            p[6] = 0; p[7] = 0;
            p[8] = 64;
            p[10] = 0; p[11] = 0;
            p[12] = 10; p[13] = (byte) 111; p[14] = (byte) 222; p[15] = 3; // src = fake DNS
            System.arraycopy(orig, 12, p, 16, 4);                          // dst = phone
            int o = ihl;
            p[o] = 0; p[o + 1] = 53;                                // src port 53
            p[o + 2] = (byte) (srcPort >> 8); p[o + 3] = (byte) srcPort;
            int ul = 8 + dns.length;
            p[o + 4] = (byte) (ul >> 8); p[o + 5] = (byte) ul;
            p[o + 6] = 0; p[o + 7] = 0;                             // UDP checksum optional over IPv4
            System.arraycopy(dns, 0, p, o + 8, dns.length);
            int c = checksum(p, 0, ihl);
            p[10] = (byte) (c >> 8); p[11] = (byte) c;
            synchronized (outLock) {
                out.write(p);
                out.flush();
            }
        } catch (Exception ignored) {
        }
    }

    private static int checksum(byte[] data, int off, int len) {
        long sum = 0;
        int i = 0;
        while (i + 1 < len) {
            sum += ((data[off + i] & 0xff) << 8) | (data[off + i + 1] & 0xff);
            i += 2;
        }
        if ((len & 1) == 1) sum += (data[off + len - 1] & 0xff) << 8;
        while (sum > 0xffff) sum = (sum & 0xffff) + (sum >> 16);
        return (int) (~sum & 0xffff);
    }

    private void createChannel() {
        NotificationManager nm = getSystemService(NotificationManager.class);
        // IMPORTANCE_LOW, not MIN: MIN would silence the "protection stopped"
        // alert too, and a warning nobody can see is the same as no warning.
        // LOW keeps the ongoing notice quiet (no sound, no heads-up).
        NotificationChannel ch = new NotificationChannel(CHANNEL, "NovaGuard protection",
                NotificationManager.IMPORTANCE_LOW);
        ch.setDescription("Shows that the content filter is active");
        nm.createNotificationChannel(ch);
    }

    private Notification buildNotification() {
        PendingIntent pi = PendingIntent.getActivity(this, 0,
                new Intent(this, MainActivity.class), PendingIntent.FLAG_IMMUTABLE);
        return new Notification.Builder(this, CHANNEL)
                .setContentTitle("NovaGuard is on")
                .setContentText("Adult content filter active — no action needed")
                .setSmallIcon(android.R.drawable.ic_secure)
                .setContentIntent(pi)
                .setOngoing(true)
                .build();
    }
}
