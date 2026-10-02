package com.novaguard.app;

import android.content.Context;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * Domain blocklist: baked into the APK + a remote list maintained by Nova.
 * No user-facing settings on purpose — the person holding the phone cannot
 * edit what gets blocked. Updates arrive via the repo Nova controls.
 */
public final class Blocklist {

    private static final String REMOTE_URL =
            "https://raw.githubusercontent.com/Charithreddy09/sentinel/main/blocklist.txt";
    private static final String CACHE = "remote_blocklist.txt";

    // Keyword net catches domains missing from the list. Deliberately aggressive.
    private static final String[] KEYWORDS = {
            "porn", "xxx", "hentai", "nsfw", "onlyfans", "pornhub", "xhamster",
            "xnxx", "xvideos", "redtube", "youporn", "spankbang", "brazzers",
            "stripchat", "chaturbate", "camsoda", "bongacams", "camgirl", "cam4",
            "erotic", "escort", "femdom", "bdsm", "milf", "nhentai", "rule34",
            "erome", "fapello", "tube8", "txxx", "upornia", "hclips", "hotmovs",
            "phub", "nude", "adult", "sex"
    };

    // Labels that contain a keyword but are NOT adult — never block these.
    private static final Set<String> WHITELIST = new HashSet<>(Arrays.asList(
            "essex", "sussex", "middlesex", "sexton", "sexsmith", "flaxseed",
            "essexcounty", "sextondiesel",
            // Substring landmines: ordinary words that merely contain a keyword.
            // Only applied when the word is the FIRST label and the domain has
            // <=3 labels and no other label trips a keyword — so an adult host
            // riding on a benign-looking first label still gets blocked.
            "sextant", "sextants", "sextile", "sextet", "sexagesimal",
            "sexism", "sexist", "sexology", "sexed", "sexing",
            "unisex", "unisexclothing", "unisexnames", "unisexsalon",
            "homosexual", "heterosexual", "intersex",
            "sexual", "sexuality", "sexually", "sexualhealth", "sexeducation",
            "adulteducation", "adulthood", "adulting",
            "escorted", "escorting", "escortservice",
            "nudism", "nudity",
            "bdsmtest", "bdsmtests",
            "cam4you",
            "milford", "militia", "military", "milestone", "mild", "mildew",
            "milk", "milky", "million", "mildred",
            "eroticart", "eroticism"
    ));

    private final Set<String> domains = new HashSet<>();
    private final Context ctx;

    public Blocklist(Context ctx) {
        this.ctx = ctx.getApplicationContext();
        loadBundled();
        loadCache();
        refreshAsync();
    }

    public synchronized boolean isBlocked(String domain) {
        if (domain == null || domain.isEmpty()) return false;
        String d = domain.toLowerCase();
        if (d.endsWith(".")) d = d.substring(0, d.length() - 1);
        String[] labels = d.split("\\.");
        // A benign-looking first label only exempts the domain when nothing else
        // in it looks adult and it isn't deeply nested (adult hosts love to hide
        // under a legit-looking subdomain). See the WHITELIST comment.
        if (labels.length > 0 && WHITELIST.contains(labels[0])) {
            if (labels.length <= 3 && !keywordHit(labels, 1)) return false;
        }
        String cur = d;
        while (true) {
            if (domains.contains(cur)) return true;
            int i = cur.indexOf('.');
            if (i < 0) break;
            cur = cur.substring(i + 1);
        }
        return keywordHit(labels, 0);
    }

    /**
     * True when any label from {@code from} onwards contains a keyword.
     * Deliberately a plain substring match: the keyword net is the backstop for
     * domains missing from the list, so it errs toward catching. False positives
     * are handled by WHITELIST above, which is the narrow, audited side.
     */
    private static boolean keywordHit(String[] labels, int from) {
        for (int i = from; i < labels.length; i++) {
            for (String kw : KEYWORDS) {
                if (labels[i].contains(kw)) return true;
            }
        }
        return false;
    }

    private void loadBundled() {
        try (InputStream is = ctx.getAssets().open("blocklist.txt")) {
            load(is);
        } catch (Exception ignored) { }
    }

    private void loadCache() {
        try (InputStream is = new FileInputStream(new File(ctx.getFilesDir(), CACHE))) {
            load(is);
        } catch (Exception ignored) { }
    }

    private synchronized void load(InputStream is) throws Exception {
        BufferedReader r = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8));
        String line;
        while ((line = r.readLine()) != null) {
            line = line.trim().toLowerCase();
            if (!line.isEmpty() && !line.startsWith("#")) domains.add(line);
        }
    }

    private void refreshAsync() {
        new Thread(() -> {
            try {
                HttpURLConnection c = (HttpURLConnection) new URL(REMOTE_URL).openConnection();
                c.setConnectTimeout(10000);
                c.setReadTimeout(10000);
                if (c.getResponseCode() != 200) return;
                StringBuilder sb = new StringBuilder();
                try (BufferedReader r = new BufferedReader(
                        new InputStreamReader(c.getInputStream(), StandardCharsets.UTF_8))) {
                    String line;
                    while ((line = r.readLine()) != null) {
                        line = line.trim().toLowerCase();
                        if (!line.isEmpty() && !line.startsWith("#")) sb.append(line).append('\n');
                    }
                }
                if (sb.length() < 10000) return; // refuse tiny/corrupt lists
                File f = new File(ctx.getFilesDir(), CACHE);
                try (FileOutputStream fo = new FileOutputStream(f)) {
                    fo.write(sb.toString().getBytes(StandardCharsets.UTF_8));
                }
                synchronized (this) { load(new FileInputStream(f)); }
            } catch (Exception ignored) { }
        }, "novaguard-list").start();
    }

    // ---------- DNS helpers ----------

    /** Extract the queried name from a DNS message. */
    public static String qname(byte[] dns) {
        try {
            StringBuilder sb = new StringBuilder();
            int i = 12;
            while (i < dns.length) {
                int len = dns[i] & 0xff;
                if (len == 0) break;
                if ((len & 0xc0) != 0 || i + 1 + len > dns.length) return null;
                for (int j = 1; j <= len; j++) {
                    sb.append((char) (dns[i + j] & 0xff));
                }
                sb.append('.');
                i += len + 1;
            }
            if (sb.length() == 0) return null;
            sb.setLength(sb.length() - 1);
            return sb.toString();
        } catch (Exception e) {
            return null;
        }
    }

    /** NXDOMAIN reply reusing the question section of the query. */
    public static byte[] nxDomain(byte[] q) {
        byte[] out = new byte[12 + (q.length - 12)];
        out[0] = q[0]; out[1] = q[1];
        out[2] = (byte) 0x81; // QR + RD
        out[3] = (byte) 0x83; // RA + rcode 3 (NXDOMAIN)
        out[4] = 0; out[5] = 1; // QDCOUNT 1
        System.arraycopy(q, 12, out, 12, q.length - 12);
        return out;
    }

    /** Build an A-record query for a hostname. */
    public static byte[] buildQuery(String host, int id) {
        String[] labels = host.split("\\.");
        int qlen = labels.length + 1; // each label prefixed by 1 len byte + NUL
        for (String l : labels) qlen += l.length();
        byte[] out = new byte[12 + qlen + 4];
        out[0] = (byte) (id >> 8); out[1] = (byte) id;
        out[2] = (byte) 0x01; // RD
        out[3] = 0;
        out[4] = 0; out[5] = 1; // QDCOUNT
        int o = 12;
        for (String l : labels) {
            out[o++] = (byte) l.length();
            for (int j = 0; j < l.length(); j++) out[o++] = (byte) l.charAt(j);
        }
        out[o++] = 0;
        out[o++] = 0; out[o++] = 1; // type A
        out[o++] = 0; out[o] = 1;   // class IN
        return out;
    }

    /** Pull A-record IPv4 addresses out of a DNS response. */
    public static byte[][] parseARecords(byte[] resp) {
        try {
            int qd = ((resp[4] & 0xff) << 8) | (resp[5] & 0xff);
            int an = ((resp[6] & 0xff) << 8) | (resp[7] & 0xff);
            int i = 12;
            for (int q = 0; q < qd && i < resp.length; q++) {
                i = skipName(resp, i);
                i += 4;
            }
            java.util.List<byte[]> ips = new java.util.ArrayList<>();
            for (int a = 0; a < an && i < resp.length; a++) {
                i = skipName(resp, i);
                int type = ((resp[i] & 0xff) << 8) | (resp[i + 1] & 0xff);
                int rdlen = ((resp[i + 8] & 0xff) << 8) | (resp[i + 9] & 0xff);
                if (type == 1 && rdlen == 4) {
                    ips.add(new byte[]{resp[i + 10], resp[i + 11], resp[i + 12], resp[i + 13]});
                }
                i += 10 + rdlen;
            }
            return ips.toArray(new byte[0][]);
        } catch (Exception e) {
            return new byte[0][];
        }
    }

    private static int skipName(byte[] d, int i) {
        while (i < d.length) {
            int len = d[i] & 0xff;
            if (len == 0) return i + 1;
            if ((len & 0xc0) != 0) return i + 2;
            i += len + 1;
        }
        return i;
    }

    /**
     * SafeSearch enforcement: map a search-engine domain to the special
     * hostname whose IPs force safe search. Null means "no mapping".
     */
    public static String safeTarget(String domain) {
        String d = domain.toLowerCase();
        // Google: any google.<tld>, plus the country variants and www.google.*
        if (d.equals("google.com") || d.equals("www.google.com")
                || d.startsWith("www.google.") || d.equals("google.co.in")
                || d.matches("google\\.[a-z.]{2,7}")) {
            return "forcesafesearch.google.com";
        }
        if (d.equals("bing.com") || d.equals("www.bing.com")) return "strict.bing.com";
        if (d.equals("youtube.com") || d.equals("www.youtube.com") || d.equals("m.youtube.com")) {
            return "restrictmoderate.youtube.com";
        }
        // Brave -- explicitly requested, was previously unenforced.
        if (d.equals("brave.com") || d.equals("www.brave.com")
                || d.equals("search.brave.com")) return "safe.search.brave.com";
        // DuckDuckGo
        if (d.equals("duckduckgo.com") || d.equals("www.duckduckgo.com")
                || d.equals("html.duckduckgo.com") || d.equals("lite.duckduckgo.com")) {
            return "safe.duckduckgo.com";
        }
        // Startpage
        if (d.equals("startpage.com") || d.equals("www.startpage.com")) {
            return "safe.startpage.com";
        }
        return null;
    }

    /** Synthesize a DNS answer: original question, A records = given IPs. */
    public static byte[] answerWith(byte[] q, byte[][] ips) {
        if (ips.length == 0) return null;
        int an = Math.min(ips.length, 4);
        int outLen = q.length + an * 16;
        byte[] out = new byte[outLen];
        System.arraycopy(q, 0, out, 0, q.length);
        out[2] = (byte) 0x81; out[3] = (byte) 0x80; // QR RD RA, rcode 0
        out[6] = 0; out[7] = (byte) an;
        int o = q.length;
        for (int i = 0; i < an; i++) {
            out[o++] = (byte) 0xc0; out[o++] = 12; // name pointer -> question
            out[o++] = 0; out[o++] = 1;            // type A
            out[o++] = 0; out[o++] = 1;            // class IN
            out[o++] = 0; out[o++] = 0; out[o++] = 0; out[o++] = 60; // ttl 60s
            out[o++] = 0; out[o++] = 4;            // rdlength
            out[o++] = ips[i][0]; out[o++] = ips[i][1];
            out[o++] = ips[i][2]; out[o++] = ips[i][3];
        }
        return out;
    }
}
