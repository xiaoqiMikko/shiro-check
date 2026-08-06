package dev.mikko.shirocheck;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Apache Shiro 版本号解析与比较。
 *
 * <p>🔴 <b>Shiro 的版本号有三种写法,而且同一条 advisory 里就会混用</b> ——
 * GitHub 的受影响区间原文里同时出现过:
 * <pre>
 *   &gt;= 2.0.0-alpha-1, &lt; 2.0.0-alpha-3     ← 带分隔符
 *   &gt;= 2.0.0alpha1,   &lt; 2.0.0alpha4       ← 不带分隔符(同一个版本的另一种写法)
 *   &gt;= 2.0-alpha,     &lt; 2.2.1             ← 两段数字 + 无序号
 *   &gt;= 1.0.0-incubating                    ← 孵化器时期的第一个版本
 * </pre>
 * 这四种必须解析成可互相比较的东西,否则区间判定会在预发布版上整片失准。
 *
 * <p>🔴 <b>限定符只认 Shiro 真实用过的那几个</b>,别放宽成 {@code [A-Za-z]+} ——
 * 那样 {@code 2.0.x} 这种通配写法也会被"成功"解析成某个预发布版,
 * 于是区间判定拿它去比较,<b>结果既不报错也不正确</b>(第 6 注 tomcat-check 踩过)。
 * 解析不了就返回 null,让调用方显式处理。
 *
 * <p>排序:同数字段时 <b>预发布排在正式版前面</b>,
 * 即 {@code 1.0.0-incubating < 1.0.0}、{@code 2.0.0-alpha-1 < 2.0.0}。
 */
public final class ShiroVersion implements Comparable<ShiroVersion> {

    private static final Pattern P = Pattern.compile(
            "^(\\d+(?:\\.\\d+)*)"                                   // 数字段
            + "(?:[.\\-_]?(incubating|alpha|beta|rc|milestone|m)"   // 限定符(可无分隔符)
            + "[.\\-_]?(\\d*))?$",                                  // 限定符序号(可缺省)
            Pattern.CASE_INSENSITIVE);

    /** 限定符排序权。正式版用 {@link #RELEASE},排在所有预发布之后。 */
    private static final int RELEASE = 100;

    private static int qualRank(String q) {
        return switch (q.toLowerCase(Locale.ROOT)) {
            case "incubating" -> 0;
            case "milestone", "m" -> 1;
            case "alpha" -> 2;
            case "beta" -> 3;
            case "rc" -> 4;
            default -> RELEASE;
        };
    }

    private final List<Integer> nums;
    private final int qual;
    private final int qualOrd;
    private final String raw;

    private ShiroVersion(List<Integer> nums, int qual, int qualOrd, String raw) {
        this.nums = nums;
        this.qual = qual;
        this.qualOrd = qualOrd;
        this.raw = raw;
    }

    /** 解析失败返回 null —— 调用方必须处理,不要用「解析不出就当 0」蒙混过去。 */
    public static ShiroVersion parse(String s) {
        if (s == null) {
            return null;
        }
        String t = s.trim();
        if (t.isEmpty()) {
            return null;
        }
        Matcher m = P.matcher(t);
        if (!m.matches()) {
            return null;
        }
        List<Integer> ns = new ArrayList<>();
        for (String part : m.group(1).split("\\.")) {
            try {
                ns.add(Integer.parseInt(part));
            } catch (NumberFormatException e) {
                return null;
            }
        }
        int q = RELEASE;
        int ord = 0;
        if (m.group(2) != null) {
            q = qualRank(m.group(2));
            String d = m.group(3);
            ord = (d == null || d.isEmpty()) ? 0 : Integer.parseInt(d);
        }
        return new ShiroVersion(ns, q, ord, t);
    }

    /** 主版本线:1.13.0 → 1;2.0.0-alpha-1 → 2。用于「你在 1.x 还是 2.x」这类提示。 */
    public int major() {
        return nums.get(0);
    }

    @Override
    public int compareTo(ShiroVersion o) {
        int n = Math.max(nums.size(), o.nums.size());
        for (int i = 0; i < n; i++) {
            // 🔴 2.0 与 2.0.0 必须相等:advisory 里 "2.0-alpha" 和 "2.0.0-alpha-0" 指同一批版本,
            //    缺省段补 0 才不会让 ">= 2.0-alpha" 这类下限把 2.0.0-alpha-1 判在区间外。
            int a = i < nums.size() ? nums.get(i) : 0;
            int b = i < o.nums.size() ? o.nums.get(i) : 0;
            if (a != b) {
                return Integer.compare(a, b);
            }
        }
        if (qual != o.qual) {
            return Integer.compare(qual, o.qual);
        }
        return Integer.compare(qualOrd, o.qualOrd);
    }

    /**
     * 区间判定,端点是否包含由调用方给出。
     *
     * <p>🔴 <b>端点开闭直接照抄 GitHub 原文,不做「上限 +1」的转换</b>:
     * advisory 写的是 {@code < 1.13.0}(开区间),第 6 注 tomcat-check 就是在
     * 「官方闭区间 ↔ GitHub first_patched」之间做换算时错位过一格。
     * 少一次换算 = 少一个能静默出错的地方。
     *
     * @param low      下限,空表示不设限
     * @param lowIncl  下限是否含端点
     * @param high     上限,空表示不设限
     * @param highIncl 上限是否含端点
     */
    public boolean inRange(String low, boolean lowIncl, String high, boolean highIncl) {
        if (low != null && !low.isEmpty()) {
            ShiroVersion lo = parse(low);
            if (lo == null) {
                return false;
            }
            int c = compareTo(lo);
            if (c < 0 || (c == 0 && !lowIncl)) {
                return false;
            }
        }
        if (high != null && !high.isEmpty()) {
            ShiroVersion hi = parse(high);
            if (hi == null) {
                return false;
            }
            int c = compareTo(hi);
            if (c > 0 || (c == 0 && !highIncl)) {
                return false;
            }
        }
        return true;
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof ShiroVersion v && compareTo(v) == 0;
    }

    @Override
    public int hashCode() {
        return nums.get(0);
    }

    @Override
    public String toString() {
        return raw;
    }
}
