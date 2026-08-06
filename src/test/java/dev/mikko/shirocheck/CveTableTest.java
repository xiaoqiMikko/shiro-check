package dev.mikko.shirocheck;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * 判定表健全性 —— 表是脚本生成的,这里验的是「生成出来的东西能不能用」。
 *
 * <p>🔴 这些测试挡的是同一类事故:<b>脚本解析失败生成了一张空壳表,而所有测试照样全绿。</b>
 */
class CveTableTest {

    private static final List<Cve> ALL = CveTable.all();

    @Test
    @DisplayName("表不能是空的,也不能只剩几条(解析失败的典型样子)")
    void tableIsPopulated() {
        assertTrue(ALL.size() >= 30, "只有 " + ALL.size() + " 条规则,判定表疑似没生成全");
        assertEquals(26, CveTable.OFFICIAL_TOTAL, "官方条目总数变了,文案里的数字要跟着改");
    }

    @Test
    @DisplayName("每条规则的字段都要完整")
    void everyRuleIsWellFormed() {
        for (Cve c : ALL) {
            assertTrue(c.id().startsWith("CVE-"), "编号不像 CVE:" + c.id());
            assertTrue(c.module().startsWith("shiro-"), c.id() + " 的模块不像 Shiro 构件:" + c.module());
            assertFalse(c.title().isEmpty(), c.id() + " 没有标题");
            assertFalse(c.rangeSource().isEmpty(), c.id() + " 没写区间来源");
            assertTrue(!c.low().isEmpty() || !c.high().isEmpty(),
                    c.id() + " 上下限都为空 —— 那会命中所有版本");
        }
    }

    @Test
    @DisplayName("🔴 触发条件不能留空 —— 留空会被读成「无条件即中招」")
    void everyRuleStatesItsTriggerCondition() {
        for (Cve c : ALL) {
            assertFalse(c.condText().isBlank(), c.id() + " 缺触发条件说明");
            assertFalse(c.condKind().isBlank(), c.id() + " 缺触发条件分类");
        }
    }

    @Test
    @DisplayName("区间端点与修复版本都必须能被解析 —— 解析不了的端点会静默判成不命中")
    void allEndpointsParse() {
        for (Cve c : ALL) {
            if (!c.low().isEmpty()) {
                assertNotNull(ShiroVersion.parse(c.low()), c.id() + " 的下限解析不了:" + c.low());
            }
            if (!c.high().isEmpty()) {
                assertNotNull(ShiroVersion.parse(c.high()), c.id() + " 的上限解析不了:" + c.high());
            }
            if (!c.fixedIn().isEmpty()) {
                assertNotNull(ShiroVersion.parse(c.fixedIn()),
                        c.id() + " 的修复版本解析不了:" + c.fixedIn());
            }
        }
    }

    @Test
    @DisplayName("下限必须小于上限 —— 反了会命中零条且完全不报错")
    void lowIsBelowHigh() {
        for (Cve c : ALL) {
            if (c.low().isEmpty() || c.high().isEmpty()) {
                continue;
            }
            ShiroVersion lo = ShiroVersion.parse(c.low());
            ShiroVersion hi = ShiroVersion.parse(c.high());
            assertTrue(lo.compareTo(hi) <= 0,
                    c.id() + " 的区间是反的:" + c.low() + " > " + c.high());
        }
    }

    @Test
    @DisplayName("⭐ 核心主张一:确实有条目进不了 Dependabot 告警,且都写明了原因")
    void silentEntriesExistAndExplainThemselves() {
        Set<String> silent = ALL.stream().filter(c -> !c.dependabotAlerts())
                .map(Cve::id).collect(Collectors.toSet());
        assertTrue(silent.size() >= 3,
                "只有 " + silent.size() + " 条进不了告警,核心主张需重新核实");

        for (Cve c : ALL) {
            if (c.dependabotAlerts()) {
                assertTrue(c.silentReason().isEmpty(),
                        c.id() + " 会告警却填了「进不了告警」的原因,自相矛盾");
            } else {
                assertFalse(c.silentReason().isBlank(),
                        c.id() + " 进不了告警却没说原因 —— 那就成了没依据的断言");
            }
        }
    }

    @Test
    @DisplayName("⭐ 核心主张二:跨模块差异真实存在,否则「按模块分活」这个卖点不成立")
    void crossModuleDifferenceIsReal() {
        Set<String> modules = ALL.stream().map(Cve::module).collect(Collectors.toSet());
        assertTrue(modules.size() >= 4, "只涉及 " + modules + ",跨模块差异化不成立");

        Set<String> coreCves = ALL.stream().filter(c -> c.module().equals("shiro-core"))
                .map(Cve::id).collect(Collectors.toSet());
        Set<String> nonCore = ALL.stream().filter(c -> !c.module().equals("shiro-core"))
                .map(Cve::id).collect(Collectors.toCollection(HashSet::new));
        nonCore.removeAll(coreCves);
        assertTrue(nonCore.size() >= 5,
                "只有 " + nonCore.size() + " 条完全不碰 shiro-core,分活带来的差异太小");
    }

    @Test
    @DisplayName("同一编号出现在多个模块上时,应当是不同的模块(不是重复行)")
    void multiModuleEntriesAreDistinct() {
        for (Cve a : ALL) {
            long same = ALL.stream()
                    .filter(b -> b.id().equals(a.id()) && b.module().equals(a.module()))
                    .count();
            assertTrue(same <= 2, a.id() + " 在 " + a.module() + " 上有 " + same + " 条规则,疑似重复");
        }
    }

    @Test
    @DisplayName("🔴 修复版本拿不到时必须标出来 —— 印一个升不上去的版本号是让用户白忙")
    void unavailableFixVersionsAreFlagged() {
        long unavailable = ALL.stream()
                .filter(c -> !c.fixedIn().isEmpty() && !c.fixedAvailable()).count();
        // 存在这类条目是常态(官方的 alpha 未必发到 Central),但必须是少数
        assertTrue(unavailable < ALL.size() / 2,
                "有 " + unavailable + "/" + ALL.size() + " 条的修复版本拿不到,探测逻辑疑似坏了");
        // 标了可获取的,版本号必须能解析 —— 不然报告里会印出个解析不了的东西当建议
        for (Cve c : ALL) {
            if (c.fixedAvailable()) {
                assertNotNull(ShiroVersion.parse(c.fixedIn()), c.id() + " 标了可获取但版本解析不了");
            }
        }
    }

    @Test
    @DisplayName("🔴 措辞红线:判定表里不许出现「一定中招」这类断言")
    void noOverclaimingWording() {
        List<String> banned = List.of("一定中招", "必然被利用", "已被攻破", "误报", "瞒报");
        for (Cve c : ALL) {
            String blob = c.condText() + c.title() + c.silentReason();
            for (String b : banned) {
                assertFalse(blob.contains(b), c.id() + " 的文案里出现了红线词:" + b);
            }
        }
    }

    @Test
    @DisplayName("DEFAULT 类必须真的是「默认配置即受影响」,其余必须给出条件")
    void defaultKindMeansWhatItSays() {
        for (Cve c : ALL) {
            if (c.defaultExposed()) {
                assertTrue(c.condText().contains("默认"), c.id() + " 标了 DEFAULT 但条件里没提默认配置");
            } else {
                assertTrue(c.condText().startsWith("仅当"),
                        c.id() + " 不是 DEFAULT,条件说明应当以「仅当」开头:" + c.condText());
            }
        }
    }
}
