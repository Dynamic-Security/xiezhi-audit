// Kotlin: symbols, calls, Spring MVC / Ktor entries, sinks, auth signals, clients and Gradle KTS
// dependencies, on small inline sources.
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { describe, expect, it } from 'vitest';
import type { StructIndex } from '@xiezhi/contracts';
import { Executor, SnapshotView, buildIndex, createSnapshot, declaredDependencies, extractConnections, loadRules } from '@xiezhi/context';

async function viewOf(files: Record<string, string>): Promise<{ view: SnapshotView; root: string }> {
  const root = mkdtempSync(join(tmpdir(), 'ca-m11kt-'));
  const src = join(root, 'repo');
  for (const [p, c] of Object.entries(files)) { mkdirSync(dirname(join(src, p)), { recursive: true }); writeFileSync(join(src, p), c); }
  const ex = new Executor({ scratchDir: join(root, 'exec') });
  const s = await createSnapshot({ source: { kind: 'local', path: src }, snapshotsDir: join(root, 'snapshots'), tmpDir: join(root, 'tmp'), executor: ex });
  return { view: new SnapshotView('repo', s.root, s.manifest), root };
}

async function indexOf(files: Record<string, string>): Promise<StructIndex> {
  const { view, root } = await viewOf(files);
  return (await buildIndex(view, loadRules(), { indexesDir: join(root, 'indexes') })).index;
}

const keys = (idx: StructIndex) => idx.entrypoints.map((e) => e.entryKey).sort();
const sinkOf = (idx: StructIndex, ruleId: string) => idx.sinks.filter((s) => s.ruleId === ruleId);

const CONTROLLER = `package com.acme.loan.web

import com.acme.loan.service.LoanService
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.web.bind.annotation.*

@RestController
@RequestMapping("/api/loans")
class LoanController(private val loanService: LoanService) {

    @GetMapping("/{id}")
    fun detail(@PathVariable id: Long): LoanView = loanService.detail(id)

    @PostMapping(value = ["/apply", "/submit"])
    fun apply(@RequestBody req: ApplyRequest): LoanView {
        validate(req)
        return loanService.apply(req)
    }

    @PreAuthorize("hasRole('ADMIN')")
    @RequestMapping(path = arrayOf("/{id}/approve"), method = [RequestMethod.PUT, RequestMethod.POST])
    fun approve(@PathVariable id: Long) = loanService.approve(id)

    @DeleteMapping
    fun purge() {}

    private fun validate(req: ApplyRequest) { require(req.amount > 0) }
}

data class ApplyRequest(val amount: Long)
`;

const SERVICE = `package com.acme.loan.service

import com.acme.loan.repo.LoanRepository
import org.springframework.stereotype.Service
import org.springframework.data.repository.findByIdOrNull

@Service
class LoanService(private val repo: LoanRepository) {
    fun detail(id: Long): LoanView = toView(repo.findByIdOrNull(id)!!)
    fun apply(req: ApplyRequest): LoanView = toView(repo.save(Loan(amount = req.amount)))
    fun approve(id: Long) {
        val loan = repo.findById(id).get()
        loan.status = "APPROVED"
        repo.save(loan.copy(amount = loan.amount + 1))
    }
    private fun toView(l: Loan) = LoanView(l.id)
    companion object {
        fun empty() = 0
    }
}
`;

describe('Kotlin: Spring MVC', () => {
  it('controller entries with class prefix, array / arrayOf paths, method lists and marker mappings', async () => {
    const idx = await indexOf({ 'src/main/kotlin/com/acme/loan/web/LoanController.kt': CONTROLLER, 'src/main/kotlin/com/acme/loan/service/LoanService.kt': SERVICE });
    expect(keys(idx)).toEqual([
      'DELETE /api/loans', 'GET /api/loans/{}', 'POST /api/loans/apply', 'POST /api/loans/submit',
      'POST /api/loans/{}/approve', 'PUT /api/loans/{}/approve',
    ]);
    const detail = idx.entrypoints.find((e) => e.entryKey === 'GET /api/loans/{}')!;
    expect(detail.framework).toBe('spring');
    expect(detail.handler).toBe('repo:src/main/kotlin/com/acme/loan/web/LoanController.kt#LoanController.detail(1)');
    const approve = idx.entrypoints.find((e) => e.entryKey === 'PUT /api/loans/{}/approve')!;
    expect(approve.authSignals).toEqual([`@PreAuthorize("hasRole('ADMIN')")`]);
    expect(detail.authSignals).toEqual([]);
  });

  it('symbols: classes, data classes, companion members, qualified names and signatures', async () => {
    const idx = await indexOf({ 'src/main/kotlin/com/acme/loan/service/LoanService.kt': SERVICE });
    const byName = (n: string) => idx.symbols.find((s) => s.name === n)!;
    expect(byName('LoanService')).toMatchObject({ kind: 'class', qualifiedName: 'com.acme.loan.service.LoanService', container: 'com.acme.loan.service' });
    expect(byName('approve')).toMatchObject({ kind: 'method', container: 'LoanService', signature: 'fun approve(id: Long)' });
    expect(byName('detail').signature).toBe('fun detail(id: Long): LoanView');
    expect(byName('empty')).toMatchObject({ kind: 'method', container: 'LoanService', symbolId: 'repo:src/main/kotlin/com/acme/loan/service/LoanService.kt#LoanService.empty(0)' });
  });

  it('calls resolve through constructor-injected properties, implicit this and same-package functions', async () => {
    const idx = await indexOf({
      'src/main/kotlin/com/acme/loan/web/LoanController.kt': CONTROLLER,
      'src/main/kotlin/com/acme/loan/service/LoanService.kt': SERVICE,
      'src/main/kotlin/com/acme/loan/service/Util.kt': `package com.acme.loan.service

fun normalize(s: String): String = s.trim()

fun String.masked(): String = normalize(this).take(3) + "***"
`,
    });
    const edge = (from: string, callee: string) => idx.callEdges.find((e) => e.from.endsWith(from) && e.calleeText === callee);
    expect(edge('LoanController.detail(1)', 'loanService.detail')).toMatchObject({ confidence: 'resolved', to: 'repo:src/main/kotlin/com/acme/loan/service/LoanService.kt#LoanService.detail(1)' });
    expect(edge('LoanController.apply(1)', 'validate')).toMatchObject({ confidence: 'resolved', to: 'repo:src/main/kotlin/com/acme/loan/web/LoanController.kt#LoanController.validate(1)' });
    expect(edge('LoanService.detail(1)', 'toView')).toMatchObject({ confidence: 'resolved' });
    expect(edge('com.acme.loan.service.masked(0)', 'normalize')).toMatchObject({ confidence: 'resolved', to: 'repo:src/main/kotlin/com/acme/loan/service/Util.kt#com.acme.loan.service.normalize(1)' });
    const ext = idx.symbols.find((s) => s.name === 'masked')!;
    expect(ext).toMatchObject({ kind: 'func', container: 'com.acme.loan.service', signature: 'fun String.masked(): String' });
  });

  it('business-sensitive points: by-id lookups, property / copy writes of state and amounts', async () => {
    const idx = await indexOf({ 'src/main/kotlin/com/acme/loan/service/LoanService.kt': SERVICE });
    expect(sinkOf(idx, 'kotlin.business.find-by-id').map((s) => s.api).sort()).toEqual(['按 ID 访问资源 findById(…)', '按 ID 访问资源 findByIdOrNull(…)']);
    expect(sinkOf(idx, 'kotlin.business.state-field').map((s) => s.api)).toEqual(['业务状态写入 .status =']);
    expect(sinkOf(idx, 'kotlin.business.amount-field').map((s) => s.api)).toEqual(['金额/数量写入 .amount =']);
    expect(sinkOf(idx, 'kotlin.business.state-field')[0]!.symbolId).toBe('repo:src/main/kotlin/com/acme/loan/service/LoanService.kt#LoanService.approve(1)');
  });

  it('Feign interfaces are clients, not entries; mis-parsed annotated declarations are recovered', async () => {
    const idx = await indexOf({
      'src/main/kotlin/a/Clients.kt': `package a

@FeignClient(name = "risk", url = "http://risk-svc")
interface RiskClient {
    @GetMapping("/risk/{id}")
    fun score(@PathVariable id: Long): Int
}
`,
      // Two annotations (one with arguments) + a following declaration: the grammar mis-parses this file as a
      // whole (annotated_expression / ERROR); per-declaration re-parsing recovers the controller.
      'src/main/kotlin/a/Mixed.kt': `package a

@RestController
@RequestMapping("/v1/items")
class ItemController(private val items: ItemService) {
    @GetMapping("/{id}")
    fun get(@PathVariable id: Long) = items.load(id)
}

object Registry { fun all() = listOf(1) }
interface ItemService { fun load(id: Long): Int }
data class Item(val id: Long)
`,
    });
    expect(keys(idx)).toEqual(['GET /v1/items/{}']);
    expect(idx.symbols.map((s) => s.name).sort()).toEqual(expect.arrayContaining(['ItemController', 'Registry', 'ItemService', 'Item', 'all', 'load']));
    expect(idx.symbols.find((s) => s.name === 'ItemService')!.kind).toBe('interface');
    expect(idx.symbols.find((s) => s.name === 'get')!.range).toEqual({ startLine: 6, endLine: 7 });
  });
});

describe('Kotlin: security configuration', () => {
  it('SecurityFilterChain DSL and fluent API, filters and interceptors', async () => {
    const idx = await indexOf({
      'src/main/kotlin/a/SecurityConfig.kt': `package a

import org.springframework.security.config.annotation.web.invoke

@Configuration
class SecurityConfig(private val jwtFilter: JwtFilter) {
    @Bean
    fun chain(http: HttpSecurity): SecurityFilterChain {
        http {
            csrf { disable() }
            authorizeHttpRequests {
                authorize("/admin/**", hasRole("ADMIN"))
                authorize(anyRequest, authenticated)
            }
        }
        return http.build()
    }

    @Bean
    fun api(http: HttpSecurity): SecurityFilterChain =
        http.authorizeHttpRequests { it.requestMatchers("/public/**").permitAll().anyRequest().authenticated() }.build()
}

class JwtFilter(private val tokens: TokenService) : OncePerRequestFilter() {
    override fun doFilterInternal(request: HttpServletRequest, response: HttpServletResponse, chain: FilterChain) {
        chain.doFilter(request, response)
    }
}

class AuthInterceptor : HandlerInterceptor {
    override fun preHandle(request: HttpServletRequest, response: HttpServletResponse, handler: Any): Boolean = true
}
`,
    });
    const sig = (kind: string) => idx.authSignals.filter((s) => s.kind === kind);
    expect(sig('filter').map((s) => s.detail)).toEqual(['JwtFilter : OncePerRequestFilter']);
    expect(sig('interceptor').map((s) => s.detail)).toEqual(['AuthInterceptor : HandlerInterceptor']);
    const cfg = sig('security_config');
    expect(cfg).toHaveLength(2);
    expect(cfg[0]!.target).toBe('repo:src/main/kotlin/a/SecurityConfig.kt#SecurityConfig.chain(1)');
    expect(cfg[0]!.detail).toMatch(/^authorizeHttpRequests \{ authorize\("\/admin\/\*\*", hasRole\("ADMIN"\)\)/);
    expect(cfg[1]!.detail).toMatch(/^http\.authorizeHttpRequests \{ it\.requestMatchers/);
  });
});

describe('Kotlin: Ktor', () => {
  it('routing DSL with nested route prefixes, authenticate blocks and same-file route functions', async () => {
    const idx = await indexOf({
      'src/main/kotlin/a/Application.kt': `package a

import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.routing.*

fun Application.module() {
    install(Authentication) {
        jwt("jwt") { }
    }
    routing {
        get("/health") { call.respondText("ok") }
        route("/api") {
            authenticate("jwt") {
                get("/orders/{id}") {
                    val id = call.parameters["id"]!!
                    call.respondText("<b>$id</b>", ContentType.Text.Html)
                }
                adminRoutes()
            }
            route("/public") {
                get { call.respondText("p") }
            }
        }
    }
}

fun Route.adminRoutes() {
    post("/admin/refund") {
        val client = HttpClient(CIO)
        client.get(call.receiveText())
    }
}

class Cache { fun get(k: String): String? = null }
fun other(c: Cache) { c.get("/not-a-route") }
`,
    });
    expect(keys(idx)).toEqual(['GET /api/orders/{}', 'GET /api/public', 'GET /health', 'POST /api/admin/refund']);
    const byKey = (k: string) => idx.entrypoints.find((e) => e.entryKey === k)!;
    expect(byKey('GET /api/orders/{}')).toMatchObject({ framework: 'ktor', middlewares: ['authenticate("jwt")'], authSignals: ['authenticate("jwt")'], handler: 'repo:src/main/kotlin/a/Application.kt#a.module(0)' });
    expect(byKey('POST /api/admin/refund')).toMatchObject({ authSignals: ['authenticate("jwt")'], handler: 'repo:src/main/kotlin/a/Application.kt#a.adminRoutes(0)' });
    expect(byKey('GET /health').authSignals).toEqual([]);
    expect(idx.authSignals.find((s) => s.kind === 'security_config')!.detail).toMatch(/^install\(Authentication\)/);
    expect(idx.authSignals.filter((s) => s.kind === 'middleware').map((s) => s.detail)).toEqual(['authenticate("jwt")']);
    expect(sinkOf(idx, 'kotlin.ktor.respond-html')).toHaveLength(1);
    expect(sinkOf(idx, 'kotlin.ktor.respond-html')[0]!.taintHint).toBe('string_concat');
    expect(sinkOf(idx, 'kotlin.ktor.http-client').map((s) => s.symbolId)).toEqual(['repo:src/main/kotlin/a/Application.kt#a.adminRoutes(0)']);
  });

  it('files without Ktor imports produce no Ktor routes', async () => {
    const idx = await indexOf({
      'src/main/kotlin/a/Dsl.kt': `package a
fun build() {
    routing {
        get("/x") { }
    }
}
`,
    });
    expect(idx.entrypoints).toEqual([]);
  });
});

describe('Kotlin: sinks', () => {
  const SINKS = `package a

import java.io.File
import java.io.ObjectInputStream
import java.net.URL
import java.nio.file.Paths
import javax.xml.parsers.DocumentBuilderFactory
import org.springframework.expression.spel.standard.SpelExpressionParser
import org.springframework.jdbc.core.JdbcTemplate

class ReportRepository(private val jdbcTemplate: JdbcTemplate, private val rest: RestTemplate) {
    fun search(owner: Long, sort: String): List<Row> {
        val sql = "select * from loan where owner_id = ? order by $sort"
        return jdbcTemplate.query(sql, arrayOf(owner)) { rs, _ -> Row(rs) }
    }
    fun byStatus(status: String) = jdbcTemplate.queryForList("select * from loan where status = '" + status + "'")
    fun byId(id: Long) = jdbcTemplate.query("select * from loan where id = ?", arrayOf(id)) { rs, _ -> Row(rs) }
    fun count() = jdbcTemplate.queryForObject("select count(*) from loan", Long::class.java)
    fun export(name: String) {
        Runtime.getRuntime().exec("tar czf /tmp/" + name)
        ProcessBuilder(listOf("gzip", "/var/data/fixed.csv")).start()
        ProcessBuilder("sh", "-c", name).start()
    }
    fun fetch(url: String) {
        URL(url).openStream()
        rest.getForObject<String>(url)
        rest.exchange("http://risk/" + url, HttpMethod.GET, null, String::class.java)
    }
    fun fetchConfigured(id: String) {
        val url = targets[id] ?: throw IllegalArgumentException("unknown target $id")
        rest.getForEntity(url, String::class.java)
    }
    fun read(name: String) = File("/data/" + name).readText()
    fun read2(name: String) = Paths.get("/data", name)
    fun eval(expr: String) = SpelExpressionParser().parseExpression(expr).value
    fun load(bytes: ByteArray) = ObjectInputStream(bytes.inputStream()).readObject()
    fun xml(s: String) = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(s)
    fun xmlSafe(s: String): Any {
        val f = DocumentBuilderFactory.newInstance()
        f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
        return f.newDocumentBuilder().parse(s)
    }
    fun redirect(target: String) = "redirect:" + target
    fun redirect2(target: String) = "redirect:$target"
    fun home() = "redirect:/home"
}
`;

  it('SQL: templates and concatenation are string_concat; literal SQL with bind values is constant', async () => {
    const idx = await indexOf({ 'src/main/kotlin/a/ReportRepository.kt': SINKS });
    const sql = sinkOf(idx, 'kotlin.jdbc.jdbc-template');
    const at = (fn: string) => sql.find((s) => s.symbolId?.endsWith(fn))!;
    expect(at('search(2)').taintHint).toBe('string_concat');
    expect(at('byStatus(1)').taintHint).toBe('string_concat');
    expect(at('byId(1)').taintHint).toBe('constant');
    expect(at('count(0)').taintHint).toBe('constant');
    expect(sql.every((s) => s.category === 'sqli')).toBe(true);
  });

  it('command, SSRF, path, expression, deserialization, XXE and redirect sinks', async () => {
    const idx = await indexOf({ 'src/main/kotlin/a/ReportRepository.kt': SINKS });
    const cats = (rule: string) => sinkOf(idx, rule).map((s) => `${s.symbolId?.split('#')[1]}:${s.category}:${s.taintHint ?? '-'}`);
    expect(cats('kotlin.jdk.runtime-exec')).toEqual(['ReportRepository.export(1):cmdi:string_concat']);
    expect(cats('kotlin.jdk.process-builder').sort()).toEqual(['ReportRepository.export(1):cmdi:-', 'ReportRepository.export(1):cmdi:constant']);
    expect(cats('kotlin.jdk.url-connection')).toEqual(['ReportRepository.fetch(1):ssrf:-']);
    expect(cats('kotlin.spring.rest-template').sort()).toEqual([
      'ReportRepository.fetch(1):ssrf:-', 'ReportRepository.fetch(1):ssrf:string_concat', 'ReportRepository.fetchConfigured(1):ssrf:-',
    ]);
    expect(cats('kotlin.jdk.file-new')).toEqual(['ReportRepository.read(1):path_traversal:string_concat']);
    expect(cats('kotlin.jdk.nio-files')).toEqual(['ReportRepository.read2(1):path_traversal:-']);
    expect(cats('kotlin.libs.spel')).toEqual(['ReportRepository.eval(1):expression_injection:-']);
    expect(cats('kotlin.jdk.object-input')).toEqual(['ReportRepository.load(1):deserialization:-']);
    expect(cats('kotlin.jdk.xml-factory')).toEqual(['ReportRepository.xml(1):xxe:-']);
    expect(cats('kotlin.spring.redirect-view').sort()).toEqual(['ReportRepository.redirect(1):open_redirect:string_concat', 'ReportRepository.redirect2(1):open_redirect:string_concat']);
  });

  it('Exposed exec only in files importing Exposed; non-JDBC query methods are not SQL sinks', async () => {
    const idx = await indexOf({
      'src/main/kotlin/a/Exposed.kt': `package a
import org.jetbrains.exposed.sql.transactions.transaction
fun raw(name: String) = transaction { exec("select * from t where n = '$name'") }
`,
      'src/main/kotlin/a/Other.kt': `package a
class Search(private val index: SearchIndex) {
    fun exec(q: String) = q
    fun run(q: String) { exec("x $q"); index.query("title:" + q) }
}
`,
    });
    expect(idx.sinks.filter((s) => s.category === 'sqli').map((s) => `${s.path}:${s.taintHint}`)).toEqual(['src/main/kotlin/a/Exposed.kt:string_concat']);
  });
});

describe('Kotlin: connections and dependencies', () => {
  it('Feign, RestTemplate, WebClient and Ktor client calls are consumed HTTP connections', async () => {
    const { view } = await viewOf({
      'src/main/kotlin/a/Clients.kt': `package a

const val RISK = "http://risk-svc"

@FeignClient(name = "user-service")
@RequestMapping("/users")
interface UserClient {
    @GetMapping("/{id}")
    fun get(@PathVariable id: Long): UserDto
    @RequestMapping(value = ["/search"], method = [RequestMethod.POST])
    fun search(q: Query): List<UserDto>
}

class Callers(private val restTemplate: RestTemplate, private val webClient: WebClient, private val client: HttpClient) {
    suspend fun run(id: Long) {
        restTemplate.getForObject("$RISK/score/$id", String::class.java)
        webClient.post().uri("http://audit/events").retrieve()
        client.get("http://billing/invoices/\${id}")
    }
}
`,
    });
    const conns = await extractConnections(view, null, null);
    const consumed = conns.filter((c) => c.side === 'consumes' && c.kind === 'http').map((c) => `${c.ruleId} ${c.key.method ?? '*'} ${c.key.pathTemplate} ${c.serviceHint ?? ''} ${c.extraction}`).sort();
    expect(consumed).toEqual([
      'kotlin.feign GET /users/{id} user-service literal',
      'kotlin.feign POST /users/search user-service literal',
      'kotlin.ktor.client GET /invoices/{?} billing partial',
      'kotlin.resttemplate GET /score/{?} risk-svc partial',
      'kotlin.webclient POST /events audit literal',
    ]);
  });

  it('build.gradle.kts dependencies are read (Kotlin DSL strings)', async () => {
    const { view } = await viewOf({
      'build.gradle.kts': `plugins {
    id("org.springframework.boot") version "3.1.0"
    kotlin("jvm") version "1.9.0"
}
dependencies {
    implementation("io.ktor:ktor-server-core:2.3.0")
    implementation("org.springframework.boot:spring-boot-starter-web")
}
`,
    });
    const deps = declaredDependencies(view);
    expect(deps.find((d) => d.name === 'io.ktor:ktor-server-core')).toMatchObject({ ecosystem: 'maven', version: '2.3.0', path: 'build.gradle.kts', line: 6 });
    expect(deps.find((d) => d.name === 'org.springframework.boot:spring-boot-starter-web')).toMatchObject({ version: '3.1.0' });
  });
});
