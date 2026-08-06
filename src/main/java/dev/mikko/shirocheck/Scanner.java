package dev.mikko.shirocheck;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.jar.Manifest;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * 扫描构建产物,找出实际装了哪些 Apache Shiro **模块**及各自版本。
 *
 * <p>🔴 <b>为什么必须扫产物而不是读 pom</b> —— 实测 {@code shiro-all-1.3.2.jar} 内部有
 * <b>6 个</b> {@code META-INF/maven/org.apache.shiro/<模块>/pom.properties}:
 * shiro-all 自身,外加 <b>shiro-core / shiro-web / shiro-spring / shiro-ehcache / shiro-quartz</b>。
 * 也就是说,一个只在 pom 里写了 {@code shiro-all} 的项目,
 * 依赖坐标层面只有 shiro-all 这一个名字(26 条 CVE 里只有 1 条挂在这个坐标上),
 * 而 <b>jar 里实际躺着 core / web / spring 三个模块的代码</b> —— 那几十条 CVE 一条都不会被按坐标告警。
 * 扫实物能把这层看穿,读 pom 不能。
 *
 * <p>能认三种形态:普通 jar、Spring Boot fat jar({@code BOOT-INF/lib/})、
 * 传统 WAR({@code WEB-INF/lib/})。
 */
public final class Scanner {

    /** 递归展开深度上限。fat jar 内的 jar 一般不再套 jar,留 2 层足够且防病态归档。 */
    private static final int MAX_DEPTH = 2;

    private static final String MVN_PREFIX = "meta-inf/maven/org.apache.shiro/";

    private static final Pattern NAME_VER =
            Pattern.compile("^(shiro-[a-z0-9\\-]*?)-(\\d[\\w.\\-]*)\\.jar$", Pattern.CASE_INSENSITIVE);

    /**
     * 扫到的一个 Shiro 模块。
     *
     * @param path     它在哪(fat jar 内的用 {@code !/} 分隔)
     * @param module   artifactId,如 shiro-core
     * @param version  版本
     * @param source   版本号取自哪里:pom.properties / MANIFEST / 文件名
     * @param insideAll 是不是从 shiro-all 这类 uber jar 里读出来的
     */
    public record Module(String path, String module, ShiroVersion version,
                         String source, boolean insideAll) {
    }

    private final List<Module> found = new ArrayList<>();
    private final List<String> warnings = new ArrayList<>();

    public List<Module> modules() {
        return found;
    }

    public List<String> warnings() {
        return warnings;
    }

    public void scan(Path target) throws IOException {
        if (!Files.exists(target)) {
            warnings.add("路径不存在:" + target);
            return;
        }
        if (Files.isDirectory(target)) {
            Files.walkFileTree(target, new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult visitFile(Path f, BasicFileAttributes a) {
                    String n = f.getFileName().toString().toLowerCase();
                    if (n.endsWith(".jar") || n.endsWith(".war") || n.endsWith(".ear")) {
                        try {
                            scanArchive(f.toString(), Files.readAllBytes(f), 0);
                        } catch (IOException e) {
                            warnings.add("读取失败 " + f + ":" + e.getMessage());
                        }
                    }
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFileFailed(Path f, IOException e) {
                    warnings.add("无法访问 " + f + ":" + e.getMessage());
                    return FileVisitResult.CONTINUE;
                }
            });
        } else {
            scanArchive(target.toString(), Files.readAllBytes(target), 0);
        }
    }

    private void scanArchive(String path, byte[] bytes, int depth) {
        List<byte[]> innerBytes = new ArrayList<>();
        List<String> innerPaths = new ArrayList<>();
        List<String> mvnCoords = new ArrayList<>();
        String mfVersion = null;

        try (ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(bytes))) {
            ZipEntry e;
            while ((e = zis.getNextEntry()) != null) {
                if (e.isDirectory()) {
                    continue;
                }
                // 🔴 ZIP 规范要求用 '/',但现实里存在写成 '\' 的归档
                // (PowerShell Compress-Archive 就是一例)。只认 '/' 的话这类归档一条都扫不出来,
                // 而「没扫到」看起来和「你很安全」一模一样(第 6 注踩过)。
                String name = e.getName().replace('\\', '/');
                String lower = name.toLowerCase();

                if (lower.startsWith(MVN_PREFIX) && lower.endsWith("/pom.properties")) {
                    String coord = readCoord(zis.readAllBytes());
                    if (coord != null) {
                        mvnCoords.add(coord);
                    }
                } else if ("meta-inf/manifest.mf".equals(lower)) {
                    mfVersion = readManifestVersion(zis);
                } else if (lower.endsWith(".jar") && depth < MAX_DEPTH) {
                    innerPaths.add(name);
                    innerBytes.add(zis.readAllBytes());
                }
            }
        } catch (IOException | IllegalArgumentException ex) {
            warnings.add("归档解析失败 " + path + ":" + ex.getMessage()
                    + "(🔴 这不等于「里面没有 Shiro」,请手工确认)");
            return;
        }

        record0(path, bytes, mvnCoords, mfVersion);

        for (int i = 0; i < innerBytes.size(); i++) {
            scanArchive(path + "!/" + innerPaths.get(i), innerBytes.get(i), depth + 1);
        }
    }

    /**
     * 把一个归档里读到的坐标落成 {@link Module}。
     *
     * <p>版本来源优先级:pom.properties(带 groupId,最可靠) &gt; MANIFEST &gt; 文件名。
     * 前两者在 jar 被改名时依然正确,文件名会骗人。
     */
    private void record0(String path, byte[] bytes, List<String> mvnCoords, String mfVersion) {
        String fileName = path.substring(Math.max(path.lastIndexOf('/'), path.lastIndexOf('\\')) + 1);

        if (!mvnCoords.isEmpty()) {
            // uber jar:自身坐标之外还带着被打进来的模块坐标。两者都要记 ——
            // 记自身是为了让「你装的是 shiro-all」这句话出现在报告里,
            // 记内含模块是为了让那些模块的 CVE 能被判出来。
            boolean uber = mvnCoords.size() > 1;
            for (String c : mvnCoords) {
                int i = c.lastIndexOf(':');
                String artifact = c.substring(0, i);
                ShiroVersion v = ShiroVersion.parse(c.substring(i + 1));
                if (v == null) {
                    warnings.add("在 " + path + " 里读到模块 " + artifact
                            + " 但版本号无法解析:" + c.substring(i + 1)
                            + "(🔴 这不等于「没有漏洞」,请手工确认版本)");
                    continue;
                }
                add(new Module(path, artifact, v, "pom.properties", uber && !isUberName(artifact)));
            }
            return;
        }

        // 没有 pom.properties(极老的构建或被重打包过)—— 退回文件名 + MANIFEST
        Matcher m = NAME_VER.matcher(fileName);
        if (!m.matches()) {
            return;                       // 不是 Shiro 构件,正常跳过
        }
        String artifact = m.group(1).toLowerCase();
        ShiroVersion v = ShiroVersion.parse(mfVersion);
        String source = "MANIFEST";
        if (v == null) {
            v = ShiroVersion.parse(m.group(2));
            source = "文件名";
        }
        if (v == null) {
            warnings.add("识别出 " + artifact + " 但取不到版本号:" + path
                    + "(🔴 这不等于「没有漏洞」,请手工确认版本)");
            return;
        }
        add(new Module(path, artifact, v, source, false));
    }

    private static boolean isUberName(String artifact) {
        return "shiro-all".equals(artifact);
    }

    /** 同一路径 + 同一模块只记一条(重复上报会让人以为有两个问题 —— 第 5 注教训)。 */
    private void add(Module mod) {
        for (Module x : found) {
            if (x.path().equals(mod.path()) && x.module().equals(mod.module())) {
                return;
            }
        }
        found.add(mod);
    }

    /**
     * 从 pom.properties 读坐标,返回 {@code artifactId:version}。
     *
     * <p>🔴 必须按 key 解析,<b>不能按行序</b>:实测同一批 jar 里键的顺序就不一样
     * (1.13.0 是 version 在前,2.0.6 是 artifactId 在前,1.7.0 前面还有一行注释)。
     */
    private static String readCoord(byte[] data) {
        Properties p = new Properties();
        try {
            p.load(new ByteArrayInputStream(data));
        } catch (IOException e) {
            return null;
        }
        String g = p.getProperty("groupId");
        String a = p.getProperty("artifactId");
        String v = p.getProperty("version");
        if (!"org.apache.shiro".equals(g) || a == null || v == null) {
            return null;                  // 只认 org.apache.shiro,防第三方同名构件
        }
        return a + ":" + v;
    }

    /**
     * 只读 MANIFEST 主属性段。
     *
     * <p>⚠️ 第 4 注(bc-check)踩过:签名 jar 的 MANIFEST 可以上兆(每个类一个条目),
     * 整段读进来会撑破缓冲。{@link Manifest} 读主属性即可,不要遍历 entries。
     */
    private static String readManifestVersion(ZipInputStream zis) {
        try {
            Manifest mf = new Manifest(new NonClosing(zis));
            String v = mf.getMainAttributes().getValue("Implementation-Version");
            return v != null ? v : mf.getMainAttributes().getValue("Bundle-Version");
        } catch (IOException | IllegalArgumentException e) {
            return null;
        }
    }

    /** Manifest 构造器会关掉流,而我们还要继续遍历同一个 ZipInputStream。 */
    private static final class NonClosing extends java.io.FilterInputStream {
        NonClosing(InputStream in) {
            super(in);
        }

        @Override
        public void close() {
            // 故意不关
        }
    }
}
