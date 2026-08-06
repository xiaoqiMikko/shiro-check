package dev.mikko.shirocheck;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class ShiroVersionTest {

    private static ShiroVersion v(String s) {
        ShiroVersion x = ShiroVersion.parse(s);
        assertNotNull(x, "应能解析:" + s);
        return x;
    }

    @Test
    @DisplayName("四种写法都要认 —— 它们在同一批 advisory 原文里混用")
    void parsesAllFourFormsSeenInAdvisories() {
        assertNotNull(ShiroVersion.parse("1.13.0"));
        assertNotNull(ShiroVersion.parse("2.0.0-alpha-1"));   // 带分隔符
        assertNotNull(ShiroVersion.parse("2.0.0alpha1"));     // 不带分隔符,同一个版本
        assertNotNull(ShiroVersion.parse("2.0-alpha"));       // 两段数字 + 无序号
        assertNotNull(ShiroVersion.parse("1.0.0-incubating"));
    }

    @Test
    @DisplayName("2.0.0-alpha-1 与 2.0.0alpha1 必须相等 —— 否则区间判定在预发布版上整片失准")
    void twoSpellingsOfSameVersionAreEqual() {
        assertEquals(v("2.0.0-alpha-1"), v("2.0.0alpha1"));
        assertEquals(v("2.0.0-alpha4"), v("2.0.0alpha4"));
    }

    @Test
    @DisplayName("预发布排在同号正式版前面")
    void prereleaseSortsBeforeRelease() {
        assertTrue(v("2.0.0-alpha-1").compareTo(v("2.0.0")) < 0);
        assertTrue(v("1.0.0-incubating").compareTo(v("1.0.0")) < 0);
        assertTrue(v("3.0.0-alpha-2").compareTo(v("3.0.0")) < 0);
    }

    @Test
    @DisplayName("缺省段补 0:2.0 与 2.0.0 相等,2.0-alpha 与 2.0.0-alpha-0 相等")
    void missingSegmentsAreZero() {
        assertEquals(v("2.0"), v("2.0.0"));
        assertEquals(v("2.0-alpha"), v("2.0.0-alpha-0"));
        assertTrue(v("2.0-alpha").compareTo(v("2.0.0-alpha-1")) < 0);
    }

    @Test
    @DisplayName("数字段按数值比,不按字符串 —— 1.9.10 > 1.9.9")
    void comparesNumerically() {
        assertTrue(v("1.9.10").compareTo(v("1.9.9")) > 0);
        assertTrue(v("1.13.0").compareTo(v("1.9.1")) > 0);
        assertTrue(v("1.10.0").compareTo(v("1.2.4")) > 0);
    }

    @Test
    @DisplayName("🔴 通配写法必须解析失败 —— 放宽限定符会让它「成功」解析成某个预发布版")
    void wildcardsMustNotParse() {
        assertNull(ShiroVersion.parse("2.0.x"));
        assertNull(ShiroVersion.parse("1.x"));
        assertNull(ShiroVersion.parse("latest"));
        assertNull(ShiroVersion.parse("2.0.0-SNAPSHOT"));
        assertNull(ShiroVersion.parse(""));
        assertNull(ShiroVersion.parse("  "));
        assertNull(ShiroVersion.parse(null));
    }

    @Test
    @DisplayName("区间端点开闭必须严格 —— advisory 写 < 1.13.0,1.13.0 本身就不该中")
    void rangeEndpointsRespectInclusivity() {
        ShiroVersion x = v("1.13.0");
        assertFalse(x.inRange("", false, "1.13.0", false), "< 1.13.0 不含 1.13.0");
        assertTrue(x.inRange("", false, "1.13.0", true), "<= 1.13.0 含 1.13.0");
        assertTrue(v("1.12.0").inRange("", false, "1.13.0", false));

        // CVE-2016-4437 的原文就是 "<= 1.2.4"
        assertTrue(v("1.2.4").inRange("", false, "1.2.4", true));
        assertFalse(v("1.2.5").inRange("", false, "1.2.4", true));
    }

    @Test
    @DisplayName("双端区间:>= 1.0.0-incubating, < 2.2.0(CVE-2026-43827 原文)")
    void twoSidedRange() {
        assertTrue(v("1.13.0").inRange("1.0.0-incubating", true, "2.2.0", false));
        assertTrue(v("1.0.0-incubating").inRange("1.0.0-incubating", true, "2.2.0", false));
        assertTrue(v("2.1.0").inRange("1.0.0-incubating", true, "2.2.0", false));
        assertFalse(v("2.2.0").inRange("1.0.0-incubating", true, "2.2.0", false));
    }

    @Test
    @DisplayName("「through 2.x 外加 3.0.0-alpha-1」靠 < 3.0.0 一条覆盖(CVE-2026-56091)")
    void through2xPlusEarly3AlphaIsOneRange() {
        assertTrue(v("1.13.0").inRange("", false, "3.0.0", false));
        assertTrue(v("2.2.1").inRange("", false, "3.0.0", false));
        assertTrue(v("3.0.0-alpha-1").inRange("", false, "3.0.0", false),
                "3.0.0-alpha-1 排在 3.0.0 之前,应落在区间内");
        assertFalse(v("3.0.0").inRange("", false, "3.0.0", false));
    }

    @Test
    @DisplayName("区间端点解析不了时判为不命中,而不是当 0 蒙混过去")
    void unparseableEndpointDoesNotSilentlyMatch() {
        assertFalse(v("1.13.0").inRange("", false, "1.13.x", false));
        assertFalse(v("1.13.0").inRange("garbage", true, "", false));
    }
}
