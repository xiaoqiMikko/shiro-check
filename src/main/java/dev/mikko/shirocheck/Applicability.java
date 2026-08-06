package dev.mikko.shirocheck;

import java.util.List;
import java.util.Map;

/**
 * 判断一条 CVE 规则对**这次扫描到的这套东西**适不适用。
 *
 * <p>这是本工具与「按坐标匹配 advisory」的唯一实质差别,所以单独成类并单独测。
 * 判定的两侧都会出错,方向不同:
 * <ul>
 *   <li><b>漏排除</b> → 拿用户根本没装的模块去吓唬他
 *       (只用 shiro-core 的人被报 shiro-spring 的洞);
 *   <li><b>误排除</b> → 真有风险却不报。<b>这一侧更糟</b> ——
 *       不报警长得和「你很安全」一模一样。
 * </ul>
 *
 * <p>🔴 <b>误排除最危险的入口是 uber jar</b>:{@code shiro-all} 里打进了 core / web / spring,
 * 但整包只有 {@code shiro-all} 一个坐标。若某个 uber jar 没留下内含模块的 pom.properties,
 * 我们就不知道里面有什么 —— 此时<b>宁可按 uber jar 的版本把所有模块的条目都判进来</b>,
 * 并在报告里说明这是保守判定,而不是默默排除。
 */
public final class Applicability {

    public enum Kind {
        /** 模块在场且版本落在受影响区间内。 */
        HIT,
        /** 没扫到这个模块 —— 这条与你无关。 */
        NOT_PRESENT,
        /** 模块在场,但版本不在受影响区间内。 */
        VERSION_SAFE
    }

    /**
     * @param kind          判定结果
     * @param reason        非 HIT 时的说明;HIT 时为空串
     * @param version       参与判定的模块版本;NOT_PRESENT 时为 null
     * @param viaOpaqueUber 是不是靠「内容不明的 uber jar」保守判进来的
     */
    public record Verdict(Kind kind, String reason, ShiroVersion version, boolean viaOpaqueUber) {
        public boolean hit() {
            return kind == Kind.HIT;
        }
    }

    /**
     * @param cve        判定表里的一条规则(已经是 CVE × 模块 粒度)
     * @param present    扫到的模块 → 该模块出现过的**所有**版本
     * @param opaqueUber 扫到了 uber jar 但读不出它内含哪些模块时,给出它的版本;否则传 null
     *
     * <p>🔴 <b>同一个模块可能有多个版本</b>(老 WAR 的 WEB-INF/lib 里塞了两代 jar、
     * 一个目录下混着多个应用)。只拿其中一个去判会漏:
     * 区间 {@code >= 1.2.4, < 3.0.0} 遇到 {1.0.0, 2.0.0} 两个版本时,
     * 挑最低的 1.0.0 判 → 判成安全,而 2.0.0 明明中。<b>任一版本命中即命中。</b>
     */
    public static Verdict judge(Cve cve, Map<String, List<ShiroVersion>> present,
                                ShiroVersion opaqueUber) {
        List<ShiroVersion> vs = present.get(cve.module());
        boolean viaUber = false;
        if (vs == null || vs.isEmpty()) {
            if (opaqueUber == null) {
                return new Verdict(Kind.NOT_PRESENT,
                        "未扫到 " + cve.module() + " 模块", null, false);
            }
            // 内容不明的 uber jar:不知道里面有没有这个模块 → 按它的版本保守判一次
            vs = List.of(opaqueUber);
            viaUber = true;
        }
        for (ShiroVersion v : vs) {
            if (v.inRange(cve.low(), cve.lowIncl(), cve.high(), cve.highIncl())) {
                return new Verdict(Kind.HIT, "", v, viaUber);
            }
        }
        ShiroVersion sample = vs.get(0);
        return new Verdict(Kind.VERSION_SAFE,
                cve.module() + " 版本 " + sample + " 不在受影响区间(" + cve.rangeText() + ")内",
                sample, viaUber);
    }

    private Applicability() {
    }
}
