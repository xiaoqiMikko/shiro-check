package dev.mikko.shirocheck;

import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * shiro-check —— 扫出你实际装的 Apache Shiro **模块**与版本,逐条判定哪些 CVE 真的落在你身上。
 *
 * <p>🔴 <b>本工具的措辞红线</b>(改输出前先读,前六注攒下来的):
 * <ul>
 *   <li>不说「Dependabot 误报 / 漏报」—— unreviewed 是 GitHub 的<b>正常流程状态</b>,
 *       按坐标匹配也是合理设计;这里只陈述「进不了告警」这个事实;
 *   <li>不说「官方瞒报」—— 26 条全部公开挂在 shiro.apache.org 上;
 *   <li>不说「你一定中招」—— 模块在场 + 版本在区间内 ≠ 可被利用,
 *       26 条里绝大多数需要特定配置,所以触发条件必须逐条列出来;
 *   <li>不解析用户配置 —— shiro.ini / application.yml / Java 代码里都能配,
 *       解析出来的结论比不解析更危险。条件明文列出,由用户自己判。
 * </ul>
 */
public final class Main {

    public static void main(String[] args) throws Exception {
        boolean utf8 = false;
        boolean showAll = false;
        List<String> targets = new ArrayList<>();
        for (String a : args) {
            switch (a) {
                // 🔴 别再试图自动探测控制台编码:Java 拿不到控制台真实代码页(第 5 注踩过整整两轮)
                case "--utf8" -> utf8 = true;
                case "--all" -> showAll = true;
                case "-h", "--help" -> {
                    usage(System.out);
                    return;
                }
                default -> targets.add(a);
            }
        }
        PrintStream out = utf8
                ? new PrintStream(new java.io.FileOutputStream(java.io.FileDescriptor.out),
                        true, StandardCharsets.UTF_8.name())
                : System.out;

        if (targets.isEmpty()) {
            usage(out);
            return;
        }

        Scanner sc = new Scanner();
        for (String t : targets) {
            sc.scan(Path.of(t));
        }
        report(out, sc, showAll);
    }

    private static void usage(PrintStream out) {
        out.println("shiro-check - Apache Shiro CVE checker (per-module)");
        // 🔴 这一行必须是纯 ASCII:控制台 chcp 与 Java 认定的编码不一致时中文会全糊,
        //    而用户恰恰是从这里才知道有 --utf8 这个开关。糊掉的帮助 = 没有帮助。
        out.println("  (Chinese text garbled? re-run with --utf8)");
        out.println();
        out.println("shiro-check —— 按模块逐条排查 Apache Shiro 的 CVE");
        out.println();
        out.println("  用法:java -jar shiro-check.jar [选项] <jar / war / 目录> ...");
        out.println();
        out.println("  --all     连「不适用」的条目也列出来(默认只提示条数)");
        out.println("  --utf8    Windows 控制台中文乱码时加这个");
        out.println();
        out.println("  判定表来源:" + CveTable.GENERATED_FROM);
        out.println("  覆盖官方 " + CveTable.OFFICIAL_TOTAL + " 条 CVE,粒度为「CVE × 模块」");
    }

    private static void report(PrintStream out, Scanner sc, boolean showAll) {
        for (String w : sc.warnings()) {
            out.println("⚠️  " + w);
        }
        List<Scanner.Module> mods = sc.modules();
        if (mods.isEmpty()) {
            out.println("没有扫到任何 Apache Shiro 模块。");
            out.println("🔴 这不等于「你没用 Shiro」—— 也可能是路径给错了,或产物还没构建。");
            return;
        }

        // 模块 → 所有出现过的版本(混合部署时同一模块可能有多个版本)
        Map<String, List<ShiroVersion>> present = new LinkedHashMap<>();
        for (Scanner.Module m : mods) {
            present.computeIfAbsent(m.module(), k -> new ArrayList<>());
            if (present.get(m.module()).stream().noneMatch(v -> v.equals(m.version()))) {
                present.get(m.module()).add(m.version());
            }
        }

        // 内容不明的 uber jar:扫到 shiro-all,却没有从它里面读出任何内含模块。
        // 🔴 此时**不知道**里面有什么 → 保守按它的版本把所有模块的条目都判进来,
        //    而不是默默排除(误排除长得和「你很安全」一模一样)。
        ShiroVersion opaqueUber = null;
        boolean sawAll = mods.stream().anyMatch(m -> m.module().equals("shiro-all"));
        boolean sawInside = mods.stream().anyMatch(Scanner.Module::insideAll);
        if (sawAll && !sawInside) {
            opaqueUber = mods.stream().filter(m -> m.module().equals("shiro-all"))
                    .map(Scanner.Module::version).findFirst().orElse(null);
        }

        printInventory(out, mods, sawInside, opaqueUber);

        Set<String> targets = new LinkedHashSet<>(present.keySet());
        if (opaqueUber != null) {
            for (Cve c : CveTable.all()) {
                targets.add(c.module());
            }
        }

        int totalHit = 0;
        int totalSilent = 0;
        Set<String> defaults = new LinkedHashSet<>();
        for (String module : targets) {
            List<Cve> hit = new ArrayList<>();
            List<Cve> notApplicable = new ArrayList<>();
            Map<String, String> reasons = new LinkedHashMap<>();
            ShiroVersion judged = null;
            for (Cve c : CveTable.all()) {
                if (!c.module().equals(module)) {
                    continue;
                }
                Applicability.Verdict v = Applicability.judge(c, present, opaqueUber);
                if (v.hit()) {
                    hit.add(c);
                    judged = v.version();
                } else {
                    notApplicable.add(c);
                    reasons.put(c.id() + "@" + c.rangeText(), v.reason());
                }
            }
            if (hit.isEmpty() && !showAll) {
                continue;
            }
            printModule(out, module, judged, hit, notApplicable, reasons, showAll,
                    opaqueUber != null && !present.containsKey(module));
            totalHit += hit.size();
            totalSilent += hit.stream().filter(c -> !c.dependabotAlerts()).count();
            hit.stream().filter(Cve::defaultExposed).forEach(c -> defaults.add(c.id()));
        }

        summarize(out, totalHit, totalSilent, defaults);
    }

    private static void printInventory(PrintStream out, List<Scanner.Module> mods,
                                       boolean sawInside, ShiroVersion opaqueUber) {
        out.println();
        out.println("扫到的 Apache Shiro 模块(" + mods.size() + " 项):");
        for (Scanner.Module m : mods) {
            out.printf("  %-30s %-16s 版本号取自 %-14s %s%n",
                    m.module(), m.version(), m.source(),
                    m.insideAll() ? "← 打在 uber jar 里" : "");
            out.println("      " + m.path());
        }
        if (sawInside) {
            out.println();
            out.println("  ⭐ 上面标了「打在 uber jar 里」的模块,在你的依赖坐标里是看不见的 ——");
            out.println("     pom 里只有 shiro-all 一个坐标,而 jar 内实际躺着这几个模块的代码。");
            out.println("     按坐标匹配的告警(如 Dependabot)对不上它们,扫实物才能看见。");
        }
        if (opaqueUber != null) {
            out.println();
            out.println("  ⚠️ 扫到 shiro-all " + opaqueUber + ",但读不出它内含哪些模块。");
            out.println("     → 下面按**保守口径**判定:把所有模块的条目都对它判一遍。");
            out.println("       宁可多列几条让你自己排除,也不默默漏掉(漏报看起来和安全一模一样)。");
        }
    }

    private static void printModule(PrintStream out, String module, ShiroVersion version,
                                    List<Cve> hit, List<Cve> na, Map<String, String> reasons,
                                    boolean showAll, boolean viaOpaqueUber) {
        out.println();
        out.println("═".repeat(78));
        out.println("模块:" + module + (version != null ? "  版本:" + version : "")
                + (viaOpaqueUber ? "  (按 uber jar 版本保守判定)" : ""));
        out.println("═".repeat(78));

        List<Cve> byDefault = hit.stream().filter(Cve::defaultExposed).toList();
        List<Cve> conditional = hit.stream().filter(c -> !c.defaultExposed()).toList();

        print(out, "🔴 默认配置即受影响 —— 优先处理", byDefault);
        print(out, "⚠️ 需满足特定条件才成立 —— 请逐条对照,不满足条件就不中", conditional);

        if (!na.isEmpty()) {
            out.println();
            out.println("── 不适用:" + na.size() + " 条 " + (showAll ? "──" : "(加 --all 查看)──"));
            if (showAll) {
                for (Cve c : na) {
                    out.println("   " + c.id() + "  " + reasons.get(c.id() + "@" + c.rangeText()));
                }
            }
        }

        if (!hit.isEmpty()) {
            // 🔴 升级目标只能从**在 Maven Central 上拿得到**的修复版本里选:
            //    有 3 条 advisory 的修复版是 3.0.0-alpha-2,而那个版本从未发布(HTTP 404)。
            //    把升不上去的版本号印成建议,是让用户去做一件做不成的事。
            String top = null;
            ShiroVersion best = null;
            for (Cve c : hit) {
                if (!c.fixedAvailable()) {
                    continue;
                }
                ShiroVersion f = ShiroVersion.parse(c.fixedIn());
                if (f != null && (best == null || f.compareTo(best) > 0)) {
                    best = f;
                    top = c.fixedIn();
                }
            }
            out.println();
            if (top != null) {
                out.println("  → " + module + " 升到 " + top + " 或更高,可覆盖以上全部 "
                        + hit.size() + " 条");
            }
            List<Cve> unavailable = hit.stream()
                    .filter(c -> !c.fixedIn().isEmpty() && !c.fixedAvailable()).toList();
            if (!unavailable.isEmpty()) {
                out.println("  ⚠️ 其中 " + unavailable.size() + " 条的官方修复版本在 Maven Central 上"
                        + "拿不到(如 "
                        + unavailable.get(0).fixedIn() + "),请升到更高的正式版:");
                for (Cve c : unavailable) {
                    out.println("       " + c.id() + " → 官方标注修复于 " + c.fixedIn());
                }
            }
        }
    }

    private static void print(PrintStream out, String header, List<Cve> list) {
        if (list.isEmpty()) {
            return;
        }
        out.println();
        out.println("── " + header + ":" + list.size() + " 条 ──");
        List<Cve> sorted = new ArrayList<>(list);
        sorted.sort(Comparator.comparingDouble((Cve c) -> -c.ghScore())
                .thenComparing(c -> -rank(c.ghSev())));
        for (Cve c : sorted) {
            out.println();
            out.println("  " + c.id() + "  " + c.title());
            out.printf("     评级:%s%s%n", c.ghSev(),
                    c.ghScore() >= 0 ? String.format("  (CVSS %.1f)", c.ghScore()) : "");
            out.println("     受影响:" + c.rangeText()
                    + (c.fixedIn().isEmpty() ? "" : "  → 修复于 " + c.fixedIn()
                            + (c.fixedAvailable() ? "" : "(⚠️ 该版本未发布到 Maven Central)")));
            out.println("     触发条件:" + c.condText());
            if (!c.dependabotAlerts()) {
                out.println("     🔴 进不了 Dependabot 告警:" + c.silentReason());
            }
            out.println("     区间来源:" + c.rangeSource());
            if (!c.desc().isEmpty()) {
                out.println("     官方原文:" + c.desc());
            }
        }
    }

    private static int rank(String s) {
        return switch (s.toLowerCase()) {
            case "low" -> 0;
            case "moderate", "medium" -> 1;
            case "important", "high" -> 2;
            case "critical" -> 3;
            default -> -1;
        };
    }

    private static void summarize(PrintStream out, int totalHit, int totalSilent,
                                  Set<String> defaults) {
        out.println();
        out.println("── 小结 ──");
        if (totalHit == 0) {
            out.println("  ✅ 判定表内没有命中你这套模块与版本的条目。");
            out.println("     判定表覆盖官方 " + CveTable.OFFICIAL_TOTAL + " 条 CVE;");
            out.println("     「没命中」= 你装的模块与版本不在这些条目的受影响范围内。");
            return;
        }
        out.println("  命中 " + totalHit + " 条(按「CVE × 模块」计),其中 "
                + totalSilent + " 条进不了 Dependabot 告警");
        out.println("  默认配置即受影响:"
                + (defaults.isEmpty() ? "无" : String.join(", ", new TreeSet<>(defaults))));
        out.println();
        out.println("  🔴 「命中」= 这个模块在场 且 版本落在官方受影响区间内,");
        out.println("     **不等于**「已被利用」或「必然可利用」——");
        out.println("     26 条里绝大多数需要特定配置才成立,请逐条对照上面的触发条件。");
    }

    private Main() {
    }
}
