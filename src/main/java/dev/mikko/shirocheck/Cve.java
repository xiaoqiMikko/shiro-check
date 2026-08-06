package dev.mikko.shirocheck;

/**
 * 一条 CVE 在**一个 Shiro 模块**上的判定规则。由 tools/gen_rules.py 生成。
 *
 * <p>🔴 <b>粒度是「CVE × 模块 × 版本区间」而不是「CVE」</b> —— 这是本工具存在的理由。
 * 同一个编号在不同模块上的受影响区间可以完全不同,例如 CVE-2020-17523
 * 同时挂在 {@code shiro-web} / {@code shiro-spring} / {@code shiro-spring-boot-starter} 上;
 * 而 CVE-2020-17510 只挂 {@code shiro-spring} —— 只用 {@code shiro-core} 的人根本不中。
 * 把它们压成一条「Shiro &lt; 1.7.1 有洞」,就等于把用户该自己做的判断替他做错了。
 */
public record Cve(
        String id,
        /** 受影响模块的 artifactId,如 shiro-core / shiro-web / shiro-spring / shiro-guice */
        String module,
        /** GitHub advisory 评级:low / medium / high / critical;没有 advisory 时为 unknown */
        String ghSev,
        /** CVSS v3 分数;-1 表示未给出 */
        double ghScore,
        /** GitHub advisory 类型:reviewed / unreviewed / none */
        String ghType,
        /** 这条会不会出现在 Dependabot 告警里 */
        boolean dependabotAlerts,
        /** 进不了告警的原因;{@link #dependabotAlerts()} 为 true 时为空串 */
        String silentReason,
        /** 受影响下限;空表示不设下限 */
        String low,
        /** 下限是否含端点 */
        boolean lowIncl,
        /** 受影响上限;空表示不设上限 */
        String high,
        /** 上限是否含端点 */
        boolean highIncl,
        /** 修复版本(升到它或更高即可覆盖本条) */
        String fixedIn,
        /**
         * 这个修复版本在 Maven Central 上**拿得到吗**。
         *
         * <p>🔴 实测有 3 条 advisory 的 first_patched_version 是 {@code 3.0.0-alpha-2},
         * 而这个版本从未发布到 Maven Central(HTTP 404)—— 官方直接发了 3.0.0 正式版。
         * 照着这种版本号去升是升不动的。<b>把一个升不了的版本印成升级建议,
         * 不是「误报」,是让用户去做一件做不成的事</b>,所以必须标出来。
         */
        boolean fixedAvailable,
        /**
         * 触发条件分类。DEFAULT = 默认配置即受影响;其余各值表示需要特定配置或特定集成方式。
         *
         * <p>🔴 工具**不解析用户配置**(shiro.ini / application.yml / Java 代码里都能配,
         * 解析出来的结论比不解析更危险)。非 DEFAULT 的条目一律照实列出条件,让用户自己判。
         */
        String condKind,
        /** 触发条件说明,对照官方描述原文,未作外推 */
        String condText,
        /** 标题 */
        String title,
        /** 官方描述原文(英文原句,非转述) */
        String desc,
        /** 这条规则的版本区间取自哪个一手源 */
        String rangeSource) {

    /** 默认配置即受影响 —— 不需要额外开启任何功能。 */
    public boolean defaultExposed() {
        return "DEFAULT".equals(condKind);
    }

    /** 区间文本,照 advisory 的开闭端点渲染,不做换算。 */
    public String rangeText() {
        StringBuilder sb = new StringBuilder();
        if (low != null && !low.isEmpty()) {
            sb.append(low).append(lowIncl ? " <= " : " < ");
        }
        sb.append("版本");
        if (high != null && !high.isEmpty()) {
            sb.append(highIncl ? " <= " : " < ").append(high);
        }
        return sb.toString();
    }
}
