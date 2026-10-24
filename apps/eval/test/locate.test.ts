// Independent function locators for Python, JS/TS, PHP, Kotlin and C#.
import { describe, expect, it } from 'vitest';
import { enclosingFunction, functionSpans, listFunctions } from '../src/locate.js';

const names = (text: string, file: string) => listFunctions(text, file).map((f) => `${f.qualified}:${f.start}-${f.end}`);

describe('function locators', () => {
  it('Python: functions, methods with decorators, nested blocks and strings', () => {
    const src = [
      '# Benchmark fixture. Never built.',
      'from flask import Flask',
      'app = Flask(__name__)',
      '',
      '@app.route("/orders/<oid>")',
      'def get_order(oid):',
      '    q = """',
      'def not_a_function(x):',
      '    """',
      '    if oid:',
      '        return db.execute("SELECT * FROM o WHERE id = %s" % oid)',
      '',
      '    return None',
      '',
      'class OrderService:',
      '    def __init__(self, db):',
      '        self.db = db',
      '',
      '    async def find(self, oid):',
      '        return await self.db.get(oid)',
      '',
      'def tail():',
      '    pass',
    ].join('\n');
    expect(names(src, 'app/views.py')).toEqual(['get_order:5-13', 'OrderService.__init__:16-17', 'OrderService.find:19-20', 'tail:22-23']);
    expect(enclosingFunction(src, 'app/views.py', 11)?.qualified).toBe('get_order');
    expect(functionSpans(src, 'app/views.py', 'OrderService.find')).toHaveLength(1);
    // Black-style multi-line signatures and decorators (opencve `_http_post_json`).
    const black = [
      '# Benchmark fixture. Never built.',
      'class WebhookNotifier(\n    BaseNotifier,\n):',
      '    @retry(',
      '        times=3,',
      '    )',
      '    def _http_post_json(',
      '        self,',
      '        url: str,',
      '        payload: dict,',
      '    ) -> dict:',
      '        resp = requests.post(url, json=payload)',
      '        return resp.json()',
      '',
      'def after():',
      '    pass',
    ].join('\n');
    expect(names(black, 'web/notify.py')).toEqual(['WebhookNotifier._http_post_json:5-14', 'after:16-17']);
  });

  it('JS / TS: function declarations, arrow functions and class methods', () => {
    const src = [
      '// Benchmark fixture. Never built.',
      "import express from 'express';",
      'const router = express.Router();',
      'export async function listUsers(req, res) {',
      '  const rows = await db.query(`SELECT * FROM u WHERE name = ${req.query.n}`);',
      '  res.json(rows);',
      '}',
      'const getUser = async (req: Request, res: Response) => {',
      "  if (req.params.id) { res.send('x'); }",
      '};',
      'class UserController {',
      '  constructor(private readonly svc: UserService) {}',
      '  async remove(id: string): Promise<void> {',
      '    await this.svc.remove(id);',
      '  }',
      '}',
      "router.get('/u/:id', getUser);",
    ].join('\n');
    expect(names(src, 'src/users.ts')).toEqual(['listUsers:4-7', 'getUser:8-10', 'UserController.constructor:12-12', 'UserController.remove:13-15']);
    // Nested templates inside substitutions and regex literals with quotes / backticks (Unleash).
    const nested = [
      '// Benchmark fixture. Never built.',
      'export class FeatureService {',
      '  describe(n: number, name: string): string {',
      "    return `${n} ${n === 1 ? 'item' : `items (there's ${name})`} done`;",
      '  }',
      '  clean(s: string) {',
      "    return s.replace(/[`'\"]/g, '').split(/\\//);",
      '  }',
      '  remove(id: string) {',
      '    return this.repo.delete(id);',
      '  }',
      '}',
    ].join('\n');
    expect(names(nested, 'src/feature-service.ts')).toEqual(['FeatureService.describe:3-5', 'FeatureService.clean:6-8', 'FeatureService.remove:9-11']);
  });

  it('PHP: functions and class methods; # attributes are not comments', () => {
    const src = [
      '<?php // Benchmark fixture. Never built.',
      'namespace App\\Http\\Controllers;',
      'class OrderController extends Controller',
      '{',
      "    #[Route('/orders/{id}', methods: ['GET'])]",
      '    public function show(Request $request, $id): JsonResponse',
      '    {',
      '        $o = DB::select("select * from orders where id = $id"); // }',
      '        return response()->json($o);',
      '    }',
      '}',
      'function helper($x) { return $x; }',
    ].join('\n');
    expect(names(src, 'app/Http/Controllers/OrderController.php')).toEqual(['OrderController.show:6-10', 'helper:12-12']);
  });

  it('Kotlin: block and expression functions, extension functions, objects', () => {
    const src = [
      '// Benchmark fixture. Never built.',
      '@RestController',
      'class OrderController(private val repo: OrderRepo) {',
      '    @GetMapping("/orders/{id}")',
      '    fun get(@PathVariable id: Long): Order? {',
      '        return repo.find(id)',
      '    }',
      '    fun count(): Int = repo.count()',
      '}',
      'fun Application.module() {',
      '    routing { get("/x") { call.respondText("}") } }',
      '}',
    ].join('\n');
    expect(names(src, 'src/main/kotlin/a/OrderController.kt')).toEqual(['OrderController.get:5-7', 'OrderController.count:8-8', 'module:10-12']);
    // A class without body must not take the next class's body (reposilite JavadocContainer).
    const two = ['// Benchmark fixture. Never built.', 'data class JavadocContainer(val dir: String, @Suppress("x") val jar: String)', '', 'internal class JavadocContainerService(private val fs: Fs) {', '    fun unpackJavadocJar(c: JavadocContainer) {', '        fs.unzip(c.jar)', '    }', '}'].join('\n');
    expect(names(two, 'a/JavadocContainerService.kt')).toEqual(['JavadocContainerService.unpackJavadocJar:5-7']);
    const ctor = ['// Benchmark fixture. Never built.', 'class JavadocFacade internal constructor(', '    private val fs: Fs,', ') : Facade {', '    fun findRawJavadocResource(p: String) = fs.read(p)', '}', 'class Svc @Inject constructor(private val r: Repo) {', '    fun run() {}', '}'].join('\n');
    expect(names(ctor, 'a/JavadocFacade.kt')).toEqual(['JavadocFacade.findRawJavadocResource:5-5', 'Svc.run:8-8']);
  });

  it('C#: methods, expression-bodied members, constructors; calls are not methods', () => {
    const src = [
      '// Benchmark fixture. Never built.',
      'namespace Shop.Controllers;',
      '[ApiController]',
      '[Route("api/[controller]")]',
      'public class OrdersController : ControllerBase',
      '{',
      '    private readonly ShopDb _db;',
      '    public OrdersController(ShopDb db) { _db = db; }',
      '    [HttpGet("{id}")]',
      '    public async Task<IActionResult> Get(string id)',
      '    {',
      '        var o = await _db.Orders.FromSqlRaw($"SELECT * FROM Orders WHERE Id = {id}").FirstAsync();',
      '        Log(id);',
      '        return Ok(o);',
      '    }',
      '    private void Log(string s) => Console.WriteLine(s);',
      '    public Stream? Open(string name) { var x = a ? b : c; return null; }',
      '}',
      'public record OrderDto(string Id);',
    ].join('\n');
    expect(names(src, 'Controllers/OrdersController.cs')).toEqual(['OrdersController.OrdersController:8-8', 'OrdersController.Get:10-15', 'OrdersController.Log:16-16', 'OrdersController.Open:17-17']);
  });
});
