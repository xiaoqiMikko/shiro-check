# -*- coding: utf-8 -*-
r"""第 8 注 shiro-check 发文前事实复核(`/publish-article` 第 0 步)。

承重论据 —— 任何一条失效,文章就变成错的:
  A. 26 条里那 5 条确实进不了 Dependabot 告警
     (3 条 unreviewed 且受影响包为 0;2 条只挂 org.apache.shiro:shiro-root)
  B. shiro-root 确实是 packaging=pom 且 Maven Central 上没有 jar
  C. 官方页面条目数仍是 26
  D. 跨模块差异仍然成立(≥7 个模块;≥13 条 CVE 完全不碰 shiro-core)
  E. shiro-all 仍是把多个模块打进去的 uber jar

🔴 这些都是**时效性**论据:GitHub 随时可能把 unreviewed 转成 reviewed、
   补上受影响坐标,官方也随时可能新增条目。复核不过 → 停下改文案,
   **不许「先发了再说」**。

🔴 本脚本刻意**不 import gen_rules**,也不读它生成的 rules_dump.json ——
   它必须是**第二个独立口径**。第 6 注 tomcat-check 的教训:所有防线验的
   都是「表里的东西对不对」,没有一条验「该在表里的是不是都在」;
   而复核若复用生成脚本的解析逻辑,就会连同它的 bug 一起复现,等于没复核。
"""
import html as htmlmod
import json
import re
import subprocess
import sys
import urllib.error
import urllib.request

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
GH = r"D:\Program Files\GitHub CLI\gh.exe"
SEC_URL = "https://shiro.apache.org/security-reports.html"
MAVEN = "https://repo1.maven.org/maven2/org/apache/shiro"
PARENT = "org.apache.shiro:shiro-root"

# 文案里写死的数字 —— 变了就必须改文章
CLAIM_TOTAL = 26
CLAIM_SILENT = 5
CLAIM_MODULES = 7
CLAIM_NON_CORE = 13
CLAIM_UNREVIEWED = ["CVE-2026-56091", "CVE-2026-56130", "CVE-2014-0074"]
CLAIM_PARENT_ONLY = ["CVE-2023-22602", "CVE-2010-3863"]

fail = []


def adv(cve):
    r = subprocess.run([GH, "api", "/advisories?cve_id=%s" % cve],
                       capture_output=True, text=True, encoding="utf-8", timeout=90)
    if r.returncode != 0:
        return None
    a = json.loads(r.stdout)
    return a[0] if a else False


def http_code(url):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        return urllib.request.urlopen(req, timeout=90).getcode()
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return None


print("═══ A1. 3 条是否仍是 unreviewed 且受影响包为 0 ═══")
for c in CLAIM_UNREVIEWED:
    a = adv(c)
    if a is None:
        print("  %-16s 🔴 拉取失败 —— 不计入结论,但也不能当它没变" % c)
        fail.append(c + " 拉取失败")
        continue
    if a is False:
        print("  %-16s 🔴 GitHub 上查不到这条 advisory 了" % c)
        fail.append(c + " advisory 消失")
        continue
    n = len(a.get("vulnerabilities") or [])
    ok = a.get("type") == "unreviewed" and n == 0
    print("  %-16s type=%-11s 包数=%-3d %s" % (c, a.get("type"), n, "✅" if ok else "🔴 已变!"))
    if not ok:
        fail.append("%s 从 unreviewed/0包 变为 %s/%d包 —— Dependabot 现在报得出来了"
                    % (c, a.get("type"), n))

print("\n═══ A2. 2 条是否仍然只挂在父 POM 坐标上 ═══")
for c in CLAIM_PARENT_ONLY:
    a = adv(c)
    if not a:
        print("  %-16s 🔴 拉取失败或已消失" % c)
        fail.append(c + " 拉取失败")
        continue
    pkgs = sorted({(v.get("package") or {}).get("name") or "" for v in (a.get("vulnerabilities") or [])})
    real = [p for p in pkgs if p.startswith("org.apache.shiro:") and p != PARENT]
    print("  %-16s %s  坐标=%s" % (c, "🔴 现在有真实构件坐标了!" if real else "✅ 仍只有父 POM",
                                 ", ".join(pkgs) or "(空)"))
    if real:
        fail.append("%s 现已列出真实坐标 %s,Dependabot 会告警了" % (c, real))

print("\n═══ B. shiro-root 是否仍是没有 jar 的父 POM ═══")
pom = http_code("%s/shiro-root/1.13.0/shiro-root-1.13.0.pom" % MAVEN)
jar = http_code("%s/shiro-root/1.13.0/shiro-root-1.13.0.jar" % MAVEN)
print("  pom=%s  jar=%s  %s" % (pom, jar, "✅" if (pom == 200 and jar == 404) else "🔴 变了!"))
if not (pom == 200 and jar == 404):
    fail.append("shiro-root 的 pom/jar 状态变了(pom=%s jar=%s)" % (pom, jar))

print("\n═══ C. 官方页面条目数(文案写的是 %d)═══" % CLAIM_TOTAL)
try:
    page = urllib.request.urlopen(urllib.request.Request(
        SEC_URL, headers={"User-Agent": "Mozilla/5.0"}), timeout=90).read().decode("utf-8", "replace")
except Exception as e:
    print("  🔴 抓取失败:%s" % str(e)[:120])
    fail.append("官方页面抓取失败")
    page = ""

# 🔴 独立口径:走目录锚点(gen_rules 的主口径走的是正文 h3 的 id 属性)
toc = sorted({m.group(1) for m in
              re.finditer(r'<a href="#cve_[\d_]+">\s*(CVE-\d{4}-\d+)\s*</a>', page)})
print("  目录锚点口径:%d 条 %s" % (len(toc), "✅" if len(toc) == CLAIM_TOTAL else "🔴 变了!"))
if len(toc) != CLAIM_TOTAL:
    fail.append("官方条目数从 %d 变成 %d(新增:见页面)" % (CLAIM_TOTAL, len(toc)))

print("\n═══ D. 跨模块差异(文案:%d 个模块,%d 条完全不碰 core)═══"
      % (CLAIM_MODULES, CLAIM_NON_CORE))
# 独立口径:直接按模块坐标向 advisory API 反查,不走「逐个 CVE 查」那条路
COORDS = ["shiro-core", "shiro-web", "shiro-spring", "shiro-spring-boot-starter",
          "shiro-spring-boot-web-starter", "shiro-all", "shiro-guice", "shiro-jakarta-ee",
          "shiro-lang", "shiro-cas", "shiro-ehcache", "shiro-quartz"]
by_mod = {}
for co in COORDS:
    r = subprocess.run([GH, "api", "/advisories?ecosystem=maven&affects=org.apache.shiro:%s"
                        "&per_page=100" % co],
                       capture_output=True, text=True, encoding="utf-8", timeout=120)
    if r.returncode != 0:
        continue
    got = {a["cve_id"] for a in json.loads(r.stdout) if a.get("cve_id")}
    if got:
        by_mod[co] = got

core = by_mod.get("shiro-core", set())
by_coord = set().union(*[v for k, v in by_mod.items() if k != "shiro-core"]) - core

# 🔴 按坐标反查**只能**数到 GitHub 标了受影响包的那些。
#    另外 5 条 GitHub 查不到坐标(3 条 unreviewed + 2 条只挂父 POM),
#    它们的模块归属是从官方原文 + 真 jar 类位置定的,同样要计入。
#    不把这层算清楚,复核数字就会比文案数字少,看起来像是文案吹了 —— 实际是两个口径。
MANUAL_MOD = {"CVE-2026-56091": "shiro-guice", "CVE-2026-56130": "shiro-web",
              "CVE-2023-22602": "shiro-web", "CVE-2010-3863": "shiro-web",
              "CVE-2014-0074": "shiro-core"}
manual_non_core = {c for c, m in MANUAL_MOD.items() if m != "shiro-core"} - core
non_core = by_coord | manual_non_core
mods = set(by_mod) | set(MANUAL_MOD.values())

print("  按坐标反查到的模块:%s" % sorted(by_mod))
print("  模块总数(含人工归属的 shiro-guice):%d 个 %s"
      % (len(mods), "✅" if len(mods) == CLAIM_MODULES else "🔴 变了!"))
print("  完全不碰 shiro-core 的 CVE:%d 条 = 坐标可查 %d + 人工归属 %d"
      % (len(non_core), len(by_coord), len(manual_non_core)))
if len(mods) != CLAIM_MODULES:
    fail.append("模块数从 %d 变成 %d" % (CLAIM_MODULES, len(mods)))
if len(non_core) != CLAIM_NON_CORE:
    fail.append("完全不碰 core 的条数从 %d 变成 %d —— 文案里的数字要改"
                % (CLAIM_NON_CORE, len(non_core)))
if len(mods) >= 4 and len(non_core) >= 5:
    print("  ✅ 跨模块差异仍然成立")

print("\n═══ E. shiro-all 是否仍是 uber jar ═══")
try:
    import io
    import zipfile
    raw = urllib.request.urlopen(urllib.request.Request(
        "%s/shiro-all/1.3.2/shiro-all-1.3.2.jar" % MAVEN,
        headers={"User-Agent": "Mozilla/5.0"}), timeout=180).read()
    inner = sorted({n.split("/")[3] for n in zipfile.ZipFile(io.BytesIO(raw)).namelist()
                    if n.startswith("META-INF/maven/org.apache.shiro/")
                    and n.endswith("pom.properties")})
    print("  shiro-all-1.3.2 内含模块坐标:%d 个 %s" % (len(inner), inner))
    if len(inner) < 3:
        fail.append("shiro-all 内只剩 %d 个模块坐标,uber jar 论据不成立" % len(inner))
    else:
        print("  ✅ uber jar 论据仍然成立")
except Exception as e:
    print("  🔴 下载/解析失败:%s" % str(e)[:120])
    fail.append("shiro-all 复验失败")

print("\n" + "=" * 62)
if fail:
    print("🔴 复核未通过,**停下改文案**,不要先发了再说:")
    for f in fail:
        print("   - %s" % f)
    sys.exit(1)
print("✅ 全部承重论据复核通过,可以往下走")
