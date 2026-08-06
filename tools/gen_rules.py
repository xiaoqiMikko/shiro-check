# -*- coding: utf-8 -*-
r"""从**两个一手源**生成 CveTable.java —— 一行都不手抄。

源 A:https://shiro.apache.org/security-reports.html   官方条目全集 + 描述原文 + 触发条件原文
源 B:GitHub Advisory API                              受影响**模块坐标** + 结构化版本区间 + 评级

🔴 本脚本存在的理由,是三个只有把两个源摆在一起才看得见的事实:

   1. **官方 26 条,GitHub 按模块坐标只能查到 21 条。** 差的 5 条不是不存在,是
      查不到:3 条 advisory 仍是 unreviewed 且受影响包为空,
      2 条挂在 `org.apache.shiro:shiro-root` —— 那是 packaging=pom 的父 POM,
      Maven Central 上**根本没有对应的 jar**(已 HTTP 404 确认),没有任何项目会依赖它。
      → 这 5 条按坐标匹配的告警一律对不上。

   2. **同一个编号在不同模块上是不同的规则。** CVE-2020-17523 同时挂 web/spring/starter,
      CVE-2020-17510 只挂 spring —— 只用 shiro-core 的人不中后者。
      压成一条「Shiro < 1.7.1 有洞」就是替用户做错了判断。

   3. **shiro-all 是 uber jar**,里面打进了 core/web/spring 的代码,
      但坐标层面只有 shiro-all 一个名字(26 条里只有 1 条挂它)。

任一断言不满足 → **中止,不写文件**(防「解析失败生成空壳表而测试照样全绿」)。
"""
import html as htmlmod
import io
import json
import os
import re
import subprocess
import sys
import urllib.request
import zipfile

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
GH = r"D:\Program Files\GitHub CLI\gh.exe"
HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "src", "main", "java", "dev", "mikko", "shirocheck", "CveTable.java")
SEC_URL = "https://shiro.apache.org/security-reports.html"
MAVEN = "https://repo1.maven.org/maven2/org/apache/shiro"

# 🔴 父 POM 坐标。Dependabot 按坐标匹配依赖树,而没有任何项目会依赖一个 packaging=pom 的构件。
#    ASSERT8 每次重跑都会去 Maven Central 确认它确实没有 jar —— 这是文章的承重论据之一。
PARENT_COORD = "org.apache.shiro:shiro-root"

# ────────────────────────── 唯一的人工输入(两张表)──────────────────────────
#
# 🔴 这两张表是本脚本仅有的人工内容,所以每一条都配了断言:
#    MANUAL_RULES 的版本串必须逐字出现在官方描述原文里(ASSERT6),
#    模块归属必须由真 jar 里的类位置证实(ASSERT7)。
#    「我记得这条是 web 的」不算依据。

# GitHub 查不到受影响坐标的条目 —— 区间与模块只能取自官方原文 + 实测。
# 格式:CVE → (模块, 下限, 下限含端点, 上限, 上限含端点, 修复版, 依据类, 官方原文里必须出现的版本串)
MANUAL_RULES = {
    # "affects all Apache Shiro versions through 2.x, and 3.0.0-alpha-1 only when using shiro-guice"
    # → "< 3.0.0" 恰好同时覆盖 1.x/2.x 和 3.0.0-alpha-1(预发布排在正式版之前)
    "CVE-2026-56091": ("shiro-guice", "", False, "3.0.0", False, "3.0.0",
                       "org/apache/shiro/guice/web", ["2.x", "3.0.0-alpha-1"]),
    # "affects all Apache Shiro versions from 1.2.4 through 2.x, and 3.0.0-alpha-1"
    "CVE-2026-56130": ("shiro-web", "1.2.4", True, "3.0.0", False, "3.0.0",
                       "CookieRememberMeManager", ["1.2.4", "3.0.0-alpha-1"]),
    # "Apache Shiro 1.x before 1.2.3, when using an LDAP server with unauthenticated bind enabled"
    "CVE-2014-0074": ("shiro-core", "", False, "1.2.3", False, "1.2.3",
                      "JndiLdapRealm", ["1.2.3"]),
    # "When using Apache Shiro before 1.11.0 together with Spring Boot 2.6+"
    "CVE-2023-22602": ("shiro-web", "", False, "1.11.0", False, "1.11.0",
                       "PathMatchingFilterChainResolver", ["1.11.0"]),
    # "Apache Shiro before 1.1.0 ... does not canonicalize URI paths"
    "CVE-2010-3863": ("shiro-web", "", False, "1.1.0", False, "1.1.0",
                      "PathMatchingFilterChainResolver", ["1.1.0"]),
}

# 触发条件。措辞逐条对照官方描述 / Mitigation 原文,**不作外推**。
# 🔴 ASSERT5 强制 26 条每条都有:留空会被读者读成「无条件即中招」。
# DEFAULT = 默认配置即受影响;其余各值都意味着「不满足这个条件就不中」。
CONDITIONS = {
    "CVE-2026-56091": ("GUICE", "仅当通过 shiro-guice 模块在 web servlet 环境下使用"),
    "CVE-2026-56130": ("REMEMBERME", "仅当启用了 RememberMe 功能"),
    "CVE-2026-49268": ("LDAP", "仅当使用 DefaultLdapRealm(用户名未转义即拼进 LDAP DN)"),
    "CVE-2026-48589": ("JAKARTA", "仅当使用 shiro-jakarta-ee 集成模块"),
    "CVE-2026-44598": ("JAKARTA", "仅当使用 shiro-jakarta-ee 集成模块,且攻击者已有合法登录凭据"),
    "CVE-2026-43827": ("DEFAULT", "默认配置即受影响(登录成功后未换新 session id)"),
    "CVE-2026-43828": ("DEFAULT", "默认配置即受影响(Shiro 原生 session 管理器与 RememberMe "
                                  "下发的 cookie 没有 Secure 属性)"),
    "CVE-2026-23903": ("FILESYSTEM", "仅当静态文件放在大小写不敏感的文件系统上(如 macOS 默认设置),"
                                     "且 Shiro 里只配了小写的 filter 路径;只影响静态文件"),
    "CVE-2026-23901": ("TIMING", "仅当攻击者能精确测量请求耗时;官方注明最可能的攻击面是本地攻击"),
    "CVE-2023-46749": ("REWRITE", "仅当与 path rewriting 一起使用,且 blockSemicolon 被关掉"
                                  "(该开关默认是开的)"),
    "CVE-2023-46750": ("FORMAUTH", "仅当使用 form 认证"),
    "CVE-2023-34478": ("NONNORMALIZED", "仅当与「按未规范化路径路由」的 API 或 web 框架一起使用"),
    "CVE-2023-22602": ("SPRINGBOOT", "仅当与 Spring Boot 2.6+ 一起使用,且未把 "
                                     "spring.mvc.pathmatch.matching-strategy 设回 ant_path_matcher"
                                     "(两边路径匹配方式不一致才成立)"),
    "CVE-2022-40664": ("DISPATCH", "仅当通过 RequestDispatcher 做 forward 或 include"),
    "CVE-2022-32532": ("REGEX", "仅当使用了 RegexRequestMatcher 且配置不当"),
    "CVE-2021-41303": ("SPRINGBOOT", "仅当在 Spring Boot 环境下按特定方式配置"),
    "CVE-2020-17523": ("SPRING", "仅当与 Spring 集成(shiro-spring / spring-boot-starter)"),
    "CVE-2020-17510": ("SPRING", "仅当与 Spring 集成(shiro-spring)"),
    "CVE-2020-13933": ("DEFAULT", "默认配置即受影响(特制请求可绕过 filter 链)"),
    "CVE-2020-11989": ("DEFAULT", "默认配置即受影响(特制请求可绕过 filter 链)"),
    "CVE-2020-1957": ("SPRING", "仅当与 Spring 动态控制器一起使用"),
    "CVE-2019-12422": ("REMEMBERME", "仅当启用了 RememberMe(padding oracle 攻击 cookie 密文)"),
    "CVE-2016-6802": ("CONTEXTPATH", "仅当应用部署在非根 context path 下"),
    "CVE-2016-4437": ("REMEMBERME", "仅当启用了 RememberMe 且仍在用默认的硬编码加密密钥"),
    "CVE-2014-0074": ("LDAP", "仅当 LDAP 服务器开启了 unauthenticated bind"
                              "(此时空用户名或空密码即可通过)"),
    "CVE-2010-3863": ("DEFAULT", "默认配置即受影响(URI 路径未做规范化即与 shiro.ini 比对)"),
}


def fetch(url, timeout=90):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        return urllib.request.urlopen(req, timeout=timeout).read().decode("utf-8", "replace")
    except Exception as e:
        sys.exit("🔴 抓取失败 %s:%s —— 拿不到 ≠ 没有条目,中止" % (url, str(e)[:150]))


# ────────────────────────── 源 A:官方 security-reports ──────────────────────────
html = fetch(SEC_URL)

# 主口径:正文的 <h3 id="cve_xxxx_xxxx"><a ...>CVE-xxxx-xxxx</a></h3>
# 🔴 编号只能从 id 属性取,**不能**从标签里的文字取 —— 标题内嵌 <a> 指向 cve.mitre.org,
#    而正文里也会引用别的编号("This vulnerability is similar to CVE-2020-1957")。
#    第 6 注 tomcat-check 正是栽在「块内第一个 CVE」上:不是少条目,是**张冠李戴**,
#    错配的条目在每一项检查里都长得完全正常。
sections = re.findall(
    r'<h3 id="cve_(\d{4})_(\d+)".*?</h3>(.*?)(?=<div class="sect2">|<div class="sect1">|</body>)',
    html, re.S)
official = {}
order = []
for yr, num, body in sections:
    cve = "CVE-%s-%s" % (yr, num)
    text = re.sub(r"<[^>]+>", " ", body)
    # 🔴 必须走 html.unescape 而不是手工 replace 几个常见实体:
    #    官方原文里有 &#8217;(右单引号)这类**数字实体**,手工列表接不住,
    #    结果就是报告里原样印出 "Shiro&#8217;s" —— 真实构件复验时抓到的。
    text = htmlmod.unescape(text)
    text = re.sub(r"\s+", " ", text).strip()
    official[cve] = text
    order.append(cve)

print("源 A:官方页面解析到 %d 条" % len(official))

# ASSERT1:官方页面必须解析出足够多的条目,否则是正则失效而非「Shiro 很太平」
assert len(official) >= 20, "🔴 ASSERT1 失败:官方页面只解析到 %d 条,正则可能已失效" % len(official)

# ASSERT2 ⭐ 完整性交叉校验 —— 用**第二个独立口径**(目录锚点)再数一遍
#
# 🔴 由来(第 6 注最贵的一条教训):所有防线验的都是「表里的东西对不对」,
#    没有一条验「该在表里的是不是都在」。正确性和完整性是两个命题 ——
#    只验前者时,漏掉的条目在每一项检查里都长得完全正常。
toc = set()
for m in re.finditer(r'<a href="#cve_[\d_]+">\s*(CVE-\d{4}-\d+)\s*</a>', html):
    toc.add(m.group(1))
print("ASSERT2 完整性:正文 h3 口径 %d 条,目录锚点口径 %d 条" % (len(official), len(toc)))
if set(official) != toc:
    print("  只在正文:%s" % sorted(set(official) - toc))
    print("  只在目录:%s" % sorted(toc - set(official)))
assert set(official) == toc, "🔴 ASSERT2 失败:两个解析口径得到的 CVE 集合不一致"

# ASSERT3:描述原文不能为空 —— 空描述会让报告里那一条看起来「没什么事」
empty = [c for c, t in official.items() if len(t) < 40]
assert not empty, "🔴 ASSERT3 失败:这些条目没解析到描述原文:%s" % empty


# ────────────────────────── 源 B:GitHub Advisory ──────────────────────────
def gh_adv(cve):
    r = subprocess.run([GH, "api", "/advisories?cve_id=%s" % cve],
                       capture_output=True, text=True, encoding="utf-8", timeout=120)
    if r.returncode != 0:
        sys.exit("🔴 GitHub API 失败(%s):%s —— 拿不到 ≠ 没有,中止" % (cve, (r.stderr or "")[:200]))
    arr = json.loads(r.stdout)
    return arr[0] if arr else None


RANGE_RE = re.compile(r"^\s*(>=|<=|<|>|=)\s*(\S+)\s*$")


def parse_range(s):
    """把 '>= 2.0.0-alpha-1, < 2.0.0-alpha-3' 拆成 (low, lowIncl, high, highIncl)。

    🔴 端点开闭**照抄不换算**:第 6 注在「官方闭区间 ↔ GitHub first_patched」之间
       做换算时错位过一格,而错位一格的判定表看起来完全正常。少一次换算 = 少一处静默出错点。
    """
    low = high = ""
    low_incl = high_incl = False
    for part in s.split(","):
        m = RANGE_RE.match(part)
        if not m:
            sys.exit("🔴 无法解析版本区间片段 %r(整段 %r)—— 解析不了就不能猜,中止" % (part, s))
        op, ver = m.group(1), m.group(2)
        if op == "=":
            return ver, True, ver, True
        if op == ">=":
            low, low_incl = ver, True
        elif op == ">":
            low, low_incl = ver, False
        elif op == "<=":
            high, high_incl = ver, True
        elif op == "<":
            high, high_incl = ver, False
    return low, low_incl, high, high_incl


print("\n拉 GitHub advisory(%d 条)..." % len(official), flush=True)
rows = []          # 每行 = CVE × 模块 × 区间
meta = {}          # CVE → 元信息
for cve in order:
    a = gh_adv(cve)
    gh_sev = (a or {}).get("severity") or "unknown"
    gh_type = (a or {}).get("type") or "none"
    gh_score = ((a or {}).get("cvss") or {}).get("score")
    vulns = (a or {}).get("vulnerabilities") or []

    real, parent_only = [], []
    for v in vulns:
        name = (v.get("package") or {}).get("name") or ""
        if not name.startswith("org.apache.shiro:"):
            continue
        (parent_only if name == PARENT_COORD else real).append(v)

    # Dependabot 会不会告警:必须是 reviewed,且受影响坐标是真实存在的构件(不是父 POM)
    alerts = gh_type == "reviewed" and bool(real)
    if alerts:
        silent = ""
    elif gh_type == "unreviewed" or not vulns:
        silent = ("GitHub advisory 仍是 unreviewed(尚未标注受影响包),"
                  "而 Dependabot 只用 reviewed 的条目做告警")
    else:
        silent = ("advisory 只挂在 %s 上 —— 那是 packaging=pom 的父 POM,"
                  "Maven Central 上没有对应的 jar,没有项目会依赖它,按坐标匹配对不上" % PARENT_COORD)

    meta[cve] = {"gh_sev": gh_sev, "gh_type": gh_type, "gh_score": gh_score,
                 "alerts": alerts, "silent": silent,
                 "pkgs": sorted({(v.get("package") or {}).get("name") for v in vulns}),
                 "summary": (a or {}).get("summary") or ""}

    if real:
        for v in real:
            mod = (v.get("package") or {}).get("name").split(":")[1]
            low, li, high, hi = parse_range(v.get("vulnerable_version_range") or "")
            rows.append({"cve": cve, "module": mod, "low": low, "low_incl": li,
                         "high": high, "high_incl": hi,
                         "fixed": v.get("first_patched_version") or "", "src": "GitHub Advisory API"})
    else:
        man = MANUAL_RULES.get(cve)
        if not man:
            sys.exit("🔴 %s 在 GitHub 上没有可用的受影响坐标,且 MANUAL_RULES 里也没有它 —— "
                     "不允许静默丢条目,中止" % cve)
        mod, low, li, high, hi, fixed, _cls, _vs = man
        rows.append({"cve": cve, "module": mod, "low": low, "low_incl": li,
                     "high": high, "high_incl": hi, "fixed": fixed,
                     "src": "shiro.apache.org 官方描述原文"})

    print("  %-16s %-10s %-9s %-30s %s" % (
        cve, gh_type, gh_sev,
        ",".join(sorted({r["module"] for r in rows if r["cve"] == cve})),
        "" if alerts else "🔴Dependabot不报"))

# ASSERT4:每条 CVE 都必须落成至少一条规则 —— 防止某条被静默丢掉
lost = [c for c in official if not any(r["cve"] == c for r in rows)]
assert not lost, "🔴 ASSERT4 失败:这些条目一条规则都没生成:%s" % lost

# ASSERT5:触发条件必须每条都有
missing = [c for c in official if c not in CONDITIONS]
assert not missing, "🔴 ASSERT5 失败:这些条目缺触发条件标注:%s" % missing
extra = [c for c in CONDITIONS if c not in official]
assert not extra, "🔴 ASSERT5 失败:CONDITIONS 里有官方页面已不存在的条目(该删):%s" % extra

# ASSERT6 ⭐ 人工区间必须逐字来自官方原文 —— 防我抄错版本号
for cve, (mod, low, li, high, hi, fixed, cls, vstrs) in MANUAL_RULES.items():
    if cve not in official:
        sys.exit("🔴 ASSERT6 失败:MANUAL_RULES 里的 %s 已不在官方页面上" % cve)
    for vs in vstrs:
        assert vs in official[cve], (
            "🔴 ASSERT6 失败:%s 的版本串 %r 在官方描述原文里找不到 —— 区间是我抄错了,不是官方改了\n"
            "     官方原文:%s" % (cve, vs, official[cve][:200]))
print("\nASSERT6 人工区间溯源:%d 条的版本串均在官方原文中逐字命中 ✅" % len(MANUAL_RULES))

# ASSERT7 ⭐ 模块归属必须由真 jar 里的类位置证实 —— 「我记得这条是 web 的」不算依据
print("\nASSERT7:下真 jar 复验人工条目的模块归属...", flush=True)
_cache = {}


def entries(module, version):
    key = (module, version)
    if key not in _cache:
        url = "%s/%s/%s/%s-%s.jar" % (MAVEN, module, version, module, version)
        try:
            raw = urllib.request.urlopen(urllib.request.Request(
                url, headers={"User-Agent": "Mozilla/5.0"}), timeout=180).read()
        except Exception as e:
            sys.exit("🔴 ASSERT7 下载失败 %s:%s —— 拿不到 ≠ 类不存在,中止" % (url, str(e)[:150]))
        _cache[key] = "\n".join(zipfile.ZipFile(io.BytesIO(raw)).namelist()).lower()
    return _cache[key]


# 各模块取一个有代表性的版本(都在各自受影响区间内)
PROBE_VER = {"shiro-core": "1.13.0", "shiro-web": "1.13.0", "shiro-guice": "1.13.0"}
for cve, (mod, low, li, high, hi, fixed, cls, vstrs) in MANUAL_RULES.items():
    blob = entries(mod, PROBE_VER[mod])
    assert cls.lower() in blob, (
        "🔴 ASSERT7 失败:%s 的依据类 %s **不在 %s 里** —— 模块归属站不住" % (cve, cls, mod))
    # 反向:归到 web 的,依据类不该同时在 core 里(否则该归 core,不然只用 core 的人会被漏报)
    if mod == "shiro-web":
        core = entries("shiro-core", PROBE_VER["shiro-core"])
        assert cls.lower() not in core, (
            "🔴 ASSERT7 反向失败:%s 的依据类 %s 在 shiro-core 里也存在 —— "
            "归到 shiro-web 会漏报只用 core 的用户" % (cve, cls))
    print("   %-16s %-34s 在 %s 内确认存在 ✅" % (cve, cls, mod))

# ASSERT8 ⭐ 父 POM 坐标确实没有 jar —— 这是「按坐标匹配对不上」的承重论据
parent_cves = [c for c in official if PARENT_COORD in (meta[c]["pkgs"] or [])]
if parent_cves:
    pom_url = "%s/shiro-root/1.13.0/shiro-root-1.13.0.pom" % MAVEN
    jar_url = "%s/shiro-root/1.13.0/shiro-root-1.13.0.jar" % MAVEN


    def http_code(url):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            return urllib.request.urlopen(req, timeout=90).getcode()
        except urllib.error.HTTPError as e:
            return e.code
        except Exception as e:
            sys.exit("🔴 ASSERT8 探测失败 %s:%s" % (url, str(e)[:120]))


    pom_code, jar_code = http_code(pom_url), http_code(jar_url)
    assert pom_code == 200 and jar_code == 404, (
        "🔴 ASSERT8 失败:shiro-root 的 pom=%s jar=%s —— "
        "「父 POM 没有 jar」这个论据不再成立,文案要改" % (pom_code, jar_code))
    print("\nASSERT8 父 POM 坐标:shiro-root pom=200 / jar=404,确认无构件 ✅ (涉及 %d 条)"
          % len(parent_cves))

# ASSERT9 ⭐ 核心主张一:确实存在进不了 Dependabot 告警的条目
silent_cves = [c for c in official if not meta[c]["alerts"]]
assert len(silent_cves) >= 3, (
    "🔴 ASSERT9 失败:只有 %d 条进不了 Dependabot 告警,核心主张需重新核实" % len(silent_cves))

# ASSERT10 ⭐ 核心主张二:跨模块 applicability 必须真的有差异
#   —— 若所有 CVE 都落在 shiro-core 上,那「按模块分活」就没有意义,这一注该停下来
by_mod = {}
for r in rows:
    by_mod.setdefault(r["module"], set()).add(r["cve"])
non_core = {c for m, cs in by_mod.items() if m != "shiro-core" for c in cs} - by_mod.get("shiro-core", set())
assert len(by_mod) >= 4, "🔴 ASSERT10 失败:只涉及 %d 个模块,跨模块差异化不成立" % len(by_mod)
assert len(non_core) >= 5, (
    "🔴 ASSERT10 失败:只有 %d 条完全不碰 shiro-core —— "
    "跨模块分活带来的差异太小,不值得以此为卖点" % len(non_core))
print("\nASSERT10 跨模块差异:%d 个模块,其中 %d 条 CVE 完全不碰 shiro-core ✅" % (len(by_mod), len(non_core)))

# ASSERT12 ⭐ 修复版本必须真的能升上去 —— 拿不到的版本号不能印成升级建议
#
# 🔴 由来(真实构件复验抓到):advisory 的 first_patched_version 里有两类坑,
#    含义完全不同,不能混为一谈:
#      (a) **写法差异** —— advisory 写 2.0.0-alpha4,Central 上的构件叫 2.0.0-alpha-4。
#          构件是有的,只是版本串对不上 → 规范化后照常用。
#      (b) **真的没发布** —— 3.0.0-alpha-2 从未发到 Central(官方直接发了 3.0.0)。
#          照它去升是升不动的 → 必须标出来,让报告改口。
#    把一个升不了的版本印成升级建议,不是「误报」,是让用户去做一件做不成的事。
print("\nASSERT12:逐个探测修复版本在 Maven Central 上拿不拿得到...", flush=True)


def maven_has(module, version):
    url = "%s/%s/%s/%s-%s.jar" % (MAVEN, module, version, module, version)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"}, method="HEAD")
        return urllib.request.urlopen(req, timeout=90).getcode() == 200
    except urllib.error.HTTPError:
        return False
    except Exception as e:
        sys.exit("🔴 ASSERT12 探测失败 %s:%s —— 拿不到 ≠ 版本不存在,中止" % (url, str(e)[:120]))


def normalize(version):
    """2.0.0alpha4 / 2.0.0-alpha4 → 2.0.0-alpha-4(Central 上的实际写法)。"""
    m = re.match(r"^(\d+(?:\.\d+)*)[.\-]?(alpha|beta|rc|incubating)[.\-]?(\d+)$", version, re.I)
    return "%s-%s-%s" % (m.group(1), m.group(2).lower(), m.group(3)) if m else None


_probe = {}
for r in rows:
    if not r["fixed"]:
        r["fixed_ok"] = False
        continue
    key = (r["module"], r["fixed"])
    if key not in _probe:
        ok = maven_has(*key)
        if not ok:
            alt = normalize(r["fixed"])
            if alt and alt != r["fixed"] and maven_has(r["module"], alt):
                print("   ✍️ %-30s %s → 写法规范化为 %s(构件存在)" % (r["module"], r["fixed"], alt))
                _probe[key] = (True, alt)
            else:
                print("   🔴 %-30s %-16s 在 Maven Central 上没有构件 —— 报告里会标注"
                      % (r["module"], r["fixed"]))
                _probe[key] = (False, r["fixed"])
        else:
            _probe[key] = (True, r["fixed"])
    r["fixed_ok"], r["fixed"] = _probe[key]

_bad = sum(1 for r in rows if r["fixed"] and not r["fixed_ok"])
# 允许存在拿不到的版本(那是官方的发布节奏),但不允许**多数**拿不到 —— 那说明探测坏了
assert _bad <= len(rows) * 0.3, (
    "🔴 ASSERT12 失败:%d/%d 条的修复版本都拿不到,探测逻辑八成坏了" % (_bad, len(rows)))
print("   共 %d 条规则,其中 %d 条的修复版本在 Central 上拿不到(已标注) ✅" % (len(rows), _bad))

# ASSERT11 ⭐ 核心主张三:shiro-all 确实是把多个模块打进去的 uber jar
_all_raw = urllib.request.urlopen(urllib.request.Request(
    "%s/shiro-all/1.3.2/shiro-all-1.3.2.jar" % MAVEN,
    headers={"User-Agent": "Mozilla/5.0"}), timeout=180).read()
_all_mods = {n.split("/")[3] for n in zipfile.ZipFile(io.BytesIO(_all_raw)).namelist()
             if n.startswith("META-INF/maven/org.apache.shiro/") and n.endswith("pom.properties")}
assert len(_all_mods) >= 3, (
    "🔴 ASSERT11 失败:shiro-all 里只读到 %d 个模块坐标(%s)—— "
    "「uber jar 里藏着别的模块」这个论据不成立" % (len(_all_mods), _all_mods))
print("ASSERT11 uber jar:shiro-all-1.3.2 内含 %d 个模块坐标 %s ✅"
      % (len(_all_mods), sorted(_all_mods)))


# ────────────────────────── 生成 Java ──────────────────────────
def jstr(s):
    return '"%s"' % (s or "").replace("\\", "\\\\").replace('"', '\\"')


out = [
    "package dev.mikko.shirocheck;",
    "",
    "import java.util.ArrayList;",
    "import java.util.Collections;",
    "import java.util.List;",
    "",
    "/**",
    " * 由 tools/gen_rules.py 从两个一手源生成,请勿手工编辑。",
    " * 源 A:https://shiro.apache.org/security-reports.html(条目全集 + 描述原文 + 触发条件)",
    " * 源 B:GitHub Advisory API(受影响模块坐标 + 结构化版本区间 + 评级)",
    " *",
    " * <p>粒度是 <b>CVE × 模块</b>:同一编号在不同模块上的受影响区间可以不同。",
    " */",
    "public final class CveTable {",
    "    private CveTable() {}",
    "",
    "    public static final String GENERATED_FROM = "
    "\"shiro.apache.org/security-reports.html + GitHub Advisory API\";",
    "",
    "    /** 官方页面上的条目总数(用于报告里说明覆盖范围)。 */",
    "    public static final int OFFICIAL_TOTAL = %d;" % len(official),
    "",
    "    private static final List<Cve> ALL = new ArrayList<>();",
    "",
    "    static {",
]
for r in rows:
    c = r["cve"]
    m = meta[c]
    kind, cond = CONDITIONS[c]
    # unreviewed 条目的 GitHub summary 就是**被截断的描述**(以 "..." 结尾),
    # 拿它当标题会在报告里印出半句话。这类改用官方原文的第一句。
    title = m["summary"]
    if not title or title.rstrip().endswith("..."):
        first = re.split(r"(?<=[.!?])\s", official[c])[0]
        title = first if len(first) <= 160 else first[:157] + "…"
    out.append("        add(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);"
               % (
                   jstr(c), jstr(r["module"]), jstr(m["gh_sev"]),
                   "%.1f" % m["gh_score"] if m["gh_score"] else "-1.0",
                   jstr(m["gh_type"]), "true" if m["alerts"] else "false", jstr(m["silent"]),
                   jstr(r["low"]), "true" if r["low_incl"] else "false",
                   jstr(r["high"]), "true" if r["high_incl"] else "false",
                   jstr(r["fixed"]), "true" if r.get("fixed_ok") else "false",
                   jstr(kind), jstr(cond), jstr(title), jstr(official[c][:400]), jstr(r["src"])))
out += [
    "    }",
    "",
    "    private static void add(String id, String module, String ghSev, double ghScore,",
    "                            String ghType, boolean alerts, String silentReason,",
    "                            String low, boolean lowIncl, String high, boolean highIncl,",
    "                            String fixedIn, boolean fixedAvailable,",
    "                            String condKind, String condText,",
    "                            String title, String desc, String rangeSource) {",
    "        ALL.add(new Cve(id, module, ghSev, ghScore, ghType, alerts, silentReason,",
    "                        low, lowIncl, high, highIncl, fixedIn, fixedAvailable,",
    "                        condKind, condText, title, desc, rangeSource));",
    "    }",
    "",
    "    public static List<Cve> all() { return Collections.unmodifiableList(ALL); }",
    "}",
]
os.makedirs(os.path.dirname(OUT), exist_ok=True)
with open(OUT, "w", encoding="utf-8") as f:
    f.write("\n".join(out) + "\n")

print("\n✅ 已生成 %s" % os.path.normpath(OUT))
print("   官方 %d 条 CVE → 展开成 %d 条「CVE × 模块」规则,覆盖 %d 个模块"
      % (len(official), len(rows), len(by_mod)))
print("   进不了 Dependabot 告警:%d 条(unreviewed %d / 只挂父 POM 坐标 %d)" % (
    len(silent_cves),
    sum(1 for c in silent_cves if meta[c]["gh_type"] == "unreviewed"),
    sum(1 for c in silent_cves if meta[c]["gh_type"] == "reviewed")))
for m in sorted(by_mod):
    print("     %-30s %d 条" % (m, len(by_mod[m])))

json.dump({"rows": rows, "meta": meta, "official": official},
          open(os.path.join(HERE, "rules_dump.json"), "w", encoding="utf-8"),
          ensure_ascii=False, indent=1)
