# shiro-check

**扫出你实际装的 Apache Shiro 模块与版本,逐条判定官方 26 条 CVE 里哪些真的落在你身上。**

零依赖单 jar,不联网,不读你的 pom —— 直接扫构建产物(jar / war / fat jar / 目录)。

```
java -jar shiro-check.jar --utf8 your-app.jar
```

---

## 为什么不是「看一眼版本号就完事」

Shiro 的 CVE **不是挂在「Shiro」上的,是挂在具体模块上的**。同一个编号在不同模块上是不同的规则:

| CVE | 受影响模块 | 只用 shiro-core 的人 |
|---|---|---|
| CVE-2020-17510 | `shiro-spring` | **不中** |
| CVE-2020-17523 | `shiro-web` / `shiro-spring` / `shiro-spring-boot-starter` | **不中** |
| CVE-2023-34478 | `shiro-web` | **不中** |
| CVE-2026-56091 | `shiro-guice` | **不中** |

官方 26 条里,**13 条完全不碰 `shiro-core`**。把它们压成一句「Shiro < 1.7.1 有洞」,
就是替用户做了他该自己做的判断 —— 而且做错了。

本工具的判定粒度是 **CVE × 模块**:26 条 CVE 展开成 **37 条规则,覆盖 7 个模块**。

## 三件按坐标匹配看不见的事

### 1. 5 条进不了 Dependabot 告警

Dependabot 按依赖坐标匹配 GitHub advisory。26 条里有 5 条对不上:

| 条目 | 为什么对不上 |
|---|---|
| CVE-2026-56091(shiro-guice 认证绕过,high) | advisory 仍是 `unreviewed`,**受影响包为空** |
| CVE-2026-56130(RememberMe cookie 永不过期) | 同上 |
| CVE-2014-0074(LDAP 空口令绕过) | 同上 |
| CVE-2023-22602(Spring Boot 2.6+ 认证绕过,high) | advisory **只挂在 `org.apache.shiro:shiro-root`** 上 |
| CVE-2010-3863 | 同上 |

而 `shiro-root` 是 `packaging=pom` 的**父 POM** —— Maven Central 上
[没有对应的 jar](https://repo1.maven.org/maven2/org/apache/shiro/shiro-root/1.13.0/)(HTTP 404),
没有任何项目会依赖它,所以按坐标匹配永远对不上。

> ℹ️ `unreviewed` 是 GitHub 的**正常流程状态**(NVD 自动导入、尚未人工标注受影响包),
> 按坐标匹配也是合理设计。这里只陈述「进不了告警」这个事实,不是说谁报错了。

### 2. uber jar 里藏着别的模块

`shiro-all` 是把多个模块打包进去的 uber jar。实测 `shiro-all-1.3.2.jar` 内部有 **6 个**
`META-INF/maven/org.apache.shiro/<模块>/pom.properties`:

```
shiro-all  shiro-core  shiro-web  shiro-spring  shiro-ehcache  shiro-quartz
```

也就是说,pom 里只写了 `shiro-all` 的项目,**坐标层面只有一个名字**
(26 条里只有 CVE-2016-6802 挂在这个坐标上),而 jar 里实际躺着 core / web / spring 三个模块的代码。

扫实物能把这层看穿。实测一个 `shiro-all-1.3.2.jar`,本工具报出 **跨 3 个模块 20 条**。

### 3. 有 3 条的官方修复版本在 Maven Central 上拿不到

3 条 advisory 的 `first_patched_version` 是 `3.0.0-alpha-2`,而这个版本**从未发布到 Maven Central**
(官方直接发了 3.0.0 正式版)。照着它去升是升不动的 —— 本工具会标注出来,并把升级建议
换成实际拿得到的版本。

## 判定不等于「你中招了」

**「命中」= 这个模块在场 且 版本落在官方受影响区间内。不等于「已被利用」或「必然可利用」。**

26 条里绝大多数需要特定配置才成立,所以工具把它们**分开列**:

- 🔴 **默认配置即受影响** —— 优先处理(如 CVE-2026-43827 session fixation)
- ⚠️ **需满足特定条件** —— 逐条给出条件,不满足就不中

条件示例(逐字对照官方描述原文,未作外推):

```
CVE-2026-49268  仅当使用 DefaultLdapRealm(用户名未转义即拼进 LDAP DN)
CVE-2023-22602  仅当与 Spring Boot 2.6+ 一起使用,且未把
                spring.mvc.pathmatch.matching-strategy 设回 ant_path_matcher
CVE-2026-23903  仅当静态文件放在大小写不敏感的文件系统上(如 macOS 默认设置),
                且 Shiro 里只配了小写的 filter 路径;只影响静态文件
```

> 🔴 **工具不解析你的配置。** shiro.ini / application.yml / Java 代码里都能配 Shiro,
> 解析出来的结论比不解析更危险。条件明文列出,由你自己判断 —— 这是有意的设计,不是偷懒。

## 用法

```bash
# 扫一个 jar / war
java -jar shiro-check.jar your-app.jar

# 扫整个目录(递归)
java -jar shiro-check.jar /path/to/libs

# 连「不适用」的条目也列出来
java -jar shiro-check.jar --all your-app.jar

# Windows 控制台中文乱码时
java -jar shiro-check.jar --utf8 your-app.jar
```

**识别能力**:普通 jar · Spring Boot fat jar(`BOOT-INF/lib/`)· 传统 WAR(`WEB-INF/lib/`)·
uber jar(`shiro-all`,展开内含模块)· 被改名的 jar(以 `pom.properties` 为准)·
用反斜杠写路径的畸形归档。

需要 **JDK 17+**。运行时零依赖。

## 判定表怎么来的

**一行都不手抄。** `tools/gen_rules.py` 从两个一手源生成:

| 源 | 提供什么 |
|---|---|
| [shiro.apache.org/security-reports.html](https://shiro.apache.org/security-reports.html) | 条目全集、描述原文、触发条件原文 |
| GitHub Advisory API | 受影响**模块坐标**、结构化版本区间、评级 |

生成过程带 **12 条断言**,任一不满足就中止不写文件(防「解析失败生成空壳表而测试照样全绿」):

- **完整性**:正文 h3 口径与目录锚点口径必须数出同一批 CVE
- **溯源**:人工填的版本区间,其版本串必须**逐字出现在官方原文里**
- **实测**:模块归属必须由**真 jar 里的类位置**证实(不接受「我记得这条是 web 的」)
- **可执行**:每个修复版本都去 Maven Central 探一次,拿不到的标注出来
- **主张**:Dependabot 盲区条数、跨模块差异、uber jar 内含模块 —— 都必须仍然成立

发文前另有 `tools/recheck_before_publish.py`,用**第二套独立口径**重新核一遍承重论据
(不 import 生成脚本,也不读它的输出 —— 复用同一套解析逻辑就会连 bug 一起复现)。

## 局限

- 只覆盖官方 security-reports 页面上的 26 条,不含未公开或第三方集成的问题
- 版本区间取自官方与 GitHub,两者口径偶有差异时以模块坐标上的结构化区间为准
- 不解析配置,因此**条件类条目需要你自己判断是否满足**
- 判定表是生成时的快照;GitHub 随时可能把 `unreviewed` 转成 `reviewed`

---

## English

**shiro-check** scans your build artifacts (jar / war / fat jar / directory) to find which
Apache Shiro **modules** you actually ship, then evaluates all **26 official CVEs** against
your exact module + version combination.

Why it exists: Shiro CVEs attach to *modules*, not to "Shiro". 13 of the 26 never touch
`shiro-core` at all. The tool works at **CVE × module** granularity (37 rules, 7 modules).

Three things coordinate-based matching cannot see:

1. **5 entries never reach Dependabot alerts** — 3 advisories are still `unreviewed` with an
   empty affected-package list; 2 are attached only to `org.apache.shiro:shiro-root`, which is
   a `packaging=pom` parent POM with **no jar on Maven Central** (HTTP 404), so no project ever
   depends on it.
2. **`shiro-all` is an uber jar** — `shiro-all-1.3.2.jar` contains 6 `pom.properties` entries
   (core, web, spring, ehcache, quartz + itself). Your pom shows one coordinate; the jar carries
   three modules' worth of code.
3. **3 advisories point at `3.0.0-alpha-2` as the fix**, a version never published to Maven
   Central. The tool flags these and suggests a version you can actually upgrade to.

A "hit" means *module present AND version within the official affected range*. It does **not**
mean exploitable — most entries require specific configuration, which the tool lists verbatim
from the official advisory. **It deliberately does not parse your configuration.**

```bash
java -jar shiro-check.jar [--all] [--utf8] <jar | war | directory> ...
```

Requires JDK 17+. No runtime dependencies. The rule table is generated from two primary sources
with 12 assertions that abort on failure; see `tools/gen_rules.py`.

## License

Apache License 2.0
