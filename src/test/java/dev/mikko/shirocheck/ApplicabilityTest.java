package dev.mikko.shirocheck;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class ApplicabilityTest {

    /** 造一条规则:module 上 [low, high) 受影响。 */
    private static Cve rule(String module, String low, String high) {
        return new Cve("CVE-0000-0000", module, "high", 7.5, "reviewed", true, "",
                low, true, high, false, high, true, "DEFAULT", "默认配置即受影响",
                "测试用", "", "测试");
    }

    private static Map<String, List<ShiroVersion>> present(String module, String... versions) {
        return Map.of(module, java.util.Arrays.stream(versions)
                .map(ShiroVersion::parse).toList());
    }

    @Test
    @DisplayName("⭐ 模块不在场 → 与你无关。只用 shiro-core 的人不该看到 shiro-spring 的洞")
    void moduleNotPresentIsNotApplicable() {
        Applicability.Verdict v = Applicability.judge(
                rule("shiro-spring", "", "1.7.0"), present("shiro-core", "1.5.0"), null);

        assertEquals(Applicability.Kind.NOT_PRESENT, v.kind());
        assertFalse(v.hit());
        assertTrue(v.reason().contains("shiro-spring"));
    }

    @Test
    @DisplayName("模块在场且版本落在区间内 → 命中")
    void presentAndInRangeHits() {
        Applicability.Verdict v = Applicability.judge(
                rule("shiro-core", "", "1.10.0"), present("shiro-core", "1.9.0"), null);

        assertTrue(v.hit());
        assertEquals("1.9.0", v.version().toString());
        assertFalse(v.viaOpaqueUber());
    }

    @Test
    @DisplayName("模块在场但版本已修 → 不命中,并说明是版本安全而不是模块不在")
    void presentButPatchedIsVersionSafe() {
        Applicability.Verdict v = Applicability.judge(
                rule("shiro-core", "", "1.10.0"), present("shiro-core", "1.13.0"), null);

        assertEquals(Applicability.Kind.VERSION_SAFE, v.kind());
        assertTrue(v.reason().contains("1.13.0"));
    }

    @Test
    @DisplayName("🔴 同模块多版本:任一命中即命中 —— 挑一个判会漏掉真有风险的那个")
    void anyVersionInRangeCounts() {
        // 区间 [1.2.4, 3.0.0):挑最低的 1.0.0 判会判成安全,而 2.0.0 明明中
        Cve c = rule("shiro-web", "1.2.4", "3.0.0");
        Applicability.Verdict v = Applicability.judge(
                c, present("shiro-web", "1.0.0", "2.0.0"), null);

        assertTrue(v.hit(), "任一版本命中就该命中");
        assertEquals("2.0.0", v.version().toString());
    }

    @Test
    @DisplayName("同模块多版本且全部已修 → 不命中")
    void allVersionsPatched() {
        Applicability.Verdict v = Applicability.judge(
                rule("shiro-core", "", "1.10.0"), present("shiro-core", "1.13.0", "2.0.6"), null);

        assertEquals(Applicability.Kind.VERSION_SAFE, v.kind());
    }

    @Test
    @DisplayName("⭐ 内容不明的 uber jar → 保守判进来,而不是默默排除")
    void opaqueUberJarJudgesConservatively() {
        ShiroVersion uber = ShiroVersion.parse("1.3.2");
        Applicability.Verdict v = Applicability.judge(
                rule("shiro-spring", "", "1.7.0"), Map.of(), uber);

        assertTrue(v.hit(), "不知道 uber jar 里有什么时,漏报比多报更糟");
        assertTrue(v.viaOpaqueUber(), "必须标记出来,好让报告说明这是保守判定");
    }

    @Test
    @DisplayName("内容不明的 uber jar,但它的版本本身已修 → 仍不命中")
    void opaqueUberStillRespectsVersion() {
        ShiroVersion uber = ShiroVersion.parse("2.2.1");
        Applicability.Verdict v = Applicability.judge(
                rule("shiro-spring", "", "1.7.0"), Map.of(), uber);

        assertEquals(Applicability.Kind.VERSION_SAFE, v.kind());
    }

    @Test
    @DisplayName("模块信息明确时,uber jar 兜底不该顶掉真实版本")
    void explicitModuleWinsOverUberFallback() {
        ShiroVersion uber = ShiroVersion.parse("1.3.2");
        Applicability.Verdict v = Applicability.judge(
                rule("shiro-core", "", "1.10.0"), present("shiro-core", "1.13.0"), uber);

        assertEquals(Applicability.Kind.VERSION_SAFE, v.kind());
        assertFalse(v.viaOpaqueUber(), "真实扫到的版本说了算");
    }

    @Test
    @DisplayName("⭐ 真实场景:uber jar 展开后,shiro-spring 的 CVE 应命中")
    void bundledModuleFromUberJarHits() {
        // Scanner 把 shiro-all 里的 shiro-spring 展开成独立模块后的样子
        Map<String, List<ShiroVersion>> p = Map.of(
                "shiro-all", List.of(ShiroVersion.parse("1.3.2")),
                "shiro-core", List.of(ShiroVersion.parse("1.3.2")),
                "shiro-spring", List.of(ShiroVersion.parse("1.3.2")));

        Applicability.Verdict v = Applicability.judge(rule("shiro-spring", "", "1.7.0"), p, null);
        assertTrue(v.hit(), "pom 里只有 shiro-all,但 jar 内确实有 shiro-spring 的代码");
        assertFalse(v.viaOpaqueUber(), "这次是读出来的,不是猜的");
    }
}
