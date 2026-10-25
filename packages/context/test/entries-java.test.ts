// Java / Kotlin entries that are not HTTP routes — sockets, queue consumers, timed jobs, commands, Thrift / Dubbo.
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { describe, expect, it } from 'vitest';
import type { EntryPoint, StructIndex } from '@xiezhi/contracts';
import { buildIndex, createSnapshot, Executor, loadRules, SnapshotView } from '@xiezhi/context';

async function indexOf(files: Record<string, string>): Promise<StructIndex> {
  const root = mkdtempSync(join(tmpdir(), 'ca-m10ent-'));
  const src = join(root, 'repo');
  for (const [p, c] of Object.entries(files)) { mkdirSync(dirname(join(src, p)), { recursive: true }); writeFileSync(join(src, p), c); }
  const ex = new Executor({ scratchDir: join(root, 'exec') });
  const s = await createSnapshot({ source: { kind: 'local', path: src }, snapshotsDir: join(root, 'snapshots'), tmpDir: join(root, 'tmp'), executor: ex });
  const view = new SnapshotView('repo', s.root, s.manifest);
  return (await buildIndex(view, loadRules(), { indexesDir: join(root, 'indexes') })).index;
}
const channelKeys = (idx: StructIndex) => idx.entrypoints.filter((e) => e.kind !== 'http').map((e) => e.entryKey).sort();
const entry = (idx: StructIndex, key: string): EntryPoint => {
  const e = idx.entrypoints.find((x) => x.entryKey === key);
  if (!e) throw new Error(`no entry ${key}; have ${idx.entrypoints.map((x) => x.entryKey).join(', ')}`);
  return e;
};
/** The handler resolves to a method symbol of the index with this `Class.method(arity)` suffix. */
const expectHandler = (idx: StructIndex, e: EntryPoint, suffix: string) => {
  expect(e.handler.endsWith(`#${suffix}`)).toBe(true);
  expect(idx.symbols.find((s) => s.symbolId === e.handler)?.kind).toBe('method');
};

describe('Java non-HTTP entries', () => {
  it('queue consumers: Kafka / RabbitMQ / JMS / RocketMQ, class-level listeners, placeholders; a plain @Service is not an entry', async () => {
    const idx = await indexOf({
      'src/main/java/shop/Consumers.java': `package shop;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.security.access.prepost.PreAuthorize;
@Component
public class Consumers {
    @KafkaListener(topics = {"orders", "refunds"}, groupId = "g")
    @PreAuthorize("hasRole('SYSTEM')")
    public void onOrder(String msg) { }
    @KafkaListener(topics = "\${app.audit-topic}")
    public void onAudit(String msg) { }
    @KafkaListener(topicPattern = "events-.*")
    public void onEvents(String msg) { }
    @RabbitListener(queues = "mail")
    public void onMail(String msg) { }
    @RabbitListener(bindings = @QueueBinding(value = @Queue("billing"), exchange = @Exchange("x")))
    void onBilling(String msg) { }
    @JmsListener(destination = "inbox")
    public void onJms(String msg) { }
    public void notAListener(String msg) { }
}
`,
      'src/main/java/shop/ClassListener.java': `package shop;
@KafkaListener(topics = "multi")
public class ClassListener {
    @KafkaHandler public void onString(String s) { }
    @KafkaHandler public void onInt(Integer i) { }
    public void helper() { }
}
`,
      'src/main/java/shop/RocketConsumer.java': `package shop;
@RocketMQMessageListener(topic = "pay", consumerGroup = "pay-group")
public class RocketConsumer implements RocketMQListener<String> {
    @Override public void onMessage(String m) { }
}
`,
      'src/main/java/shop/PlainService.java': `package shop;
import org.springframework.stereotype.Service;
@Service
public class PlainService implements UserApi {
    public String get(String id) { return id; }
}
`,
    });
    expect(channelKeys(idx)).toEqual([
      'mq:jms:inbox', 'mq:kafka:${app.audit-topic}', 'mq:kafka:events-.*', 'mq:kafka:multi', 'mq:kafka:multi', 'mq:kafka:orders,refunds',
      'mq:rabbitmq:billing', 'mq:rabbitmq:mail', 'mq:rocketmq:pay',
    ]);
    const order = entry(idx, 'mq:kafka:orders,refunds');
    expect(order).toMatchObject({ kind: 'message', protocol: 'kafka', framework: 'spring-kafka', pathTemplate: 'orders,refunds', ruleId: 'java.kafka.listener' });
    expect(order.httpMethod).toBeUndefined();
    expect(order.authSignals).toEqual(['@PreAuthorize("hasRole(\'SYSTEM\')")']);
    expectHandler(idx, order, 'Consumers.onOrder(1)');
    expect(entry(idx, 'mq:kafka:${app.audit-topic}').pathTemplate).toBe('${app.audit-topic}');
    expect(entry(idx, 'mq:rabbitmq:billing')).toMatchObject({ protocol: 'rabbitmq', framework: 'spring-amqp', pathTemplate: 'billing' });
    expect(entry(idx, 'mq:jms:inbox')).toMatchObject({ protocol: 'jms', framework: 'spring-jms' });
    const rocket = entry(idx, 'mq:rocketmq:pay');
    expect(rocket).toMatchObject({ protocol: 'rocketmq', framework: 'rocketmq-spring', pathTemplate: 'pay' });
    expectHandler(idx, rocket, 'RocketConsumer.onMessage(1)');
    const multi = idx.entrypoints.filter((e) => e.entryKey === 'mq:kafka:multi').map((e) => e.handler.split('#')[1]).sort();
    expect(multi).toEqual(['ClassListener.onInt(1)', 'ClassListener.onString(1)']);
  });

  it('scheduled jobs: cron / fixedRate / fixedDelayString and XXL-Job', async () => {
    const idx = await indexOf({
      'src/main/java/shop/Jobs.java': `package shop;
@Component
public class Jobs {
    @Scheduled(cron = "0 0 3 * * *")
    public void nightly() { }
    @Scheduled(fixedRate = 5000)
    public void poll() { }
    @Scheduled(fixedDelayString = "\${jobs.delay}")
    public void sweep() { }
    @XxlJob("syncUsers")
    public void sync() { }
    public void notScheduled() { }
}
`,
    });
    expect(channelKeys(idx)).toEqual(['cron:Jobs.nightly', 'cron:Jobs.poll', 'cron:Jobs.sweep', 'cron:Jobs.sync']);
    const nightly = entry(idx, 'cron:Jobs.nightly');
    expect(nightly).toMatchObject({ kind: 'schedule', protocol: 'cron', framework: 'spring', pathTemplate: '0 0 3 * * *', ruleId: 'java.scheduled' });
    expectHandler(idx, nightly, 'Jobs.nightly(0)');
    expect(entry(idx, 'cron:Jobs.poll').pathTemplate).toBe('fixedRate=5000');
    expect(entry(idx, 'cron:Jobs.sweep').pathTemplate).toBe('fixedDelayString=${jobs.delay}');
    expect(entry(idx, 'cron:Jobs.sync')).toMatchObject({ framework: 'xxl-job', pathTemplate: 'syncUsers' });
  });

  it('sockets: @ServerEndpoint, Spring addHandler, STOMP @MessageMapping with class prefix; @RequestMapping stays HTTP', async () => {
    const idx = await indexOf({
      'src/main/java/shop/ChatEndpoint.java': `package shop;
import jakarta.websocket.server.ServerEndpoint;
@ServerEndpoint("/ws/chat/{room}")
public class ChatEndpoint {
    @OnOpen public void open(Session s) { }
    @OnMessage public void message(String text, Session s) { }
}
`,
      'src/main/java/shop/WsConfig.java': `package shop;
@Configuration
@EnableWebSocket
public class WsConfig implements WebSocketConfigurer {
    @Override
    public void registerWebSocketHandlers(WebSocketHandlerRegistry registry) {
        registry.addHandler(new EchoHandler(), "/echo", "/echo2").setAllowedOrigins("*");
        registry.addHandler(notifyHandler(), "/notify");
    }
    @Bean public NotifyHandler notifyHandler() { return new NotifyHandler(); }
}
class EchoHandler extends TextWebSocketHandler {
    @Override protected void handleTextMessage(WebSocketSession s, TextMessage m) { }
}
`,
      'src/main/java/shop/NotifyHandler.java': `package shop;
public class NotifyHandler extends TextWebSocketHandler {
    @Override protected void handleTextMessage(WebSocketSession s, TextMessage m) { }
}
`,
      'src/main/java/shop/StompController.java': `package shop;
@Controller
@MessageMapping("/room")
public class StompController {
    @MessageMapping("/send")
    public void send(String msg) { }
    @SubscribeMapping("/topic")
    public String sub() { return ""; }
    @RequestMapping("/http")
    public String http() { return ""; }
}
`,
    });
    expect(channelKeys(idx)).toEqual(['stomp:/room/send', 'stomp:/room/topic', 'ws:/echo', 'ws:/echo2', 'ws:/notify', 'ws:/ws/chat/{room}']);
    const chat = entry(idx, 'ws:/ws/chat/{room}');
    expect(chat).toMatchObject({ kind: 'socket', protocol: 'websocket', framework: 'jakarta-websocket', pathTemplate: '/ws/chat/{room}', ruleId: 'java.websocket.endpoint' });
    expectHandler(idx, chat, 'ChatEndpoint.message(2)');
    const echo = entry(idx, 'ws:/echo');
    expect(echo).toMatchObject({ framework: 'spring-websocket', pathTemplate: '/echo' });
    expectHandler(idx, echo, 'EchoHandler.handleTextMessage(2)');
    expectHandler(idx, entry(idx, 'ws:/notify'), 'NotifyHandler.handleTextMessage(2)');
    const send = entry(idx, 'stomp:/room/send');
    expect(send).toMatchObject({ kind: 'socket', protocol: 'stomp', framework: 'spring-messaging', pathTemplate: '/room/send', ruleId: 'java.stomp.message' });
    expectHandler(idx, send, 'StompController.send(1)');
    expect(idx.entrypoints.find((e) => e.kind === 'http')).toMatchObject({ entryKey: 'ANY /http' }); // the class @MessageMapping is not an HTTP prefix;
  });

  it('RPC: Thrift Iface implementations and Dubbo services (one entry per public method)', async () => {
    const idx = await indexOf({
      'src/main/java/shop/UserServiceImpl.java': `package shop;
public class UserServiceImpl implements UserService.Iface {
    @Override public User getUser(long id) throws TException { return null; }
    @Override public void deleteUser(long id) { }
    private void audit() { }
    public static UserServiceImpl create() { return null; }
}
`,
      'src/main/java/shop/OrderFacadeImpl.java': `package shop;
import org.apache.dubbo.config.annotation.DubboService;
@DubboService(version = "1.0.0")
public class OrderFacadeImpl implements OrderFacade {
    public Order find(String id) { return null; }
    void internal() { }
}
`,
      'src/main/java/shop/LegacyDubbo.java': `package shop;
import com.alibaba.dubbo.config.annotation.Service;
@Service(interfaceClass = PayFacade.class)
public class LegacyDubbo implements PayFacade, Serializable {
    public void pay(String id) { }
}
`,
    });
    expect(channelKeys(idx)).toEqual([
      'rpc:dubbo:OrderFacade/find', 'rpc:dubbo:PayFacade/pay', 'rpc:thrift:UserService/deleteUser', 'rpc:thrift:UserService/getUser',
    ]);
    const get = entry(idx, 'rpc:thrift:UserService/getUser');
    expect(get).toMatchObject({ kind: 'rpc', protocol: 'thrift', framework: 'thrift', pathTemplate: 'UserService/getUser', ruleId: 'java.thrift.iface' });
    expectHandler(idx, get, 'UserServiceImpl.getUser(1)');
    const find = entry(idx, 'rpc:dubbo:OrderFacade/find');
    expect(find).toMatchObject({ kind: 'rpc', protocol: 'dubbo', framework: 'dubbo', pathTemplate: 'OrderFacade/find', ruleId: 'java.dubbo.service' });
    expectHandler(idx, find, 'OrderFacadeImpl.find(1)');
  });

  it('commands: picocli @Command classes and subcommand methods, Spring Shell, CommandLineRunner', async () => {
    const idx = await indexOf({
      'src/main/java/tool/ImportCmd.java': `package tool;
import picocli.CommandLine.Command;
@Command(name = "import-users", mixinStandardHelpOptions = true)
public class ImportCmd implements Callable<Integer> {
    public Integer call() { return 0; }
    @Command(name = "dry-run")
    void dryRun() { }
}
`,
      'src/main/java/tool/ShellCommands.java': `package tool;
import org.springframework.shell.standard.ShellMethod;
@ShellComponent
public class ShellCommands {
    @ShellMethod(key = "reset-password", value = "Reset a password")
    public String reset(String user) { return ""; }
    @ShellMethod("List users")
    public String listUsers() { return ""; }
}
`,
      'src/main/java/tool/Shell3.java': `package tool;
import org.springframework.shell.command.annotation.Command;
@Command(command = "admin")
public class Shell3 {
    @Command(command = "purge")
    public void purge() { }
}
`,
      'src/main/java/tool/Startup.java': `package tool;
@Component
public class Startup implements CommandLineRunner {
    @Override public void run(String... args) { }
}
`,
    });
    expect(channelKeys(idx)).toEqual(['cli:Startup', 'cli:admin purge', 'cli:import-users', 'cli:import-users dry-run', 'cli:list-users', 'cli:reset-password']);
    const imp = entry(idx, 'cli:import-users');
    expect(imp).toMatchObject({ kind: 'cli', protocol: 'cli', framework: 'picocli', pathTemplate: 'import-users', ruleId: 'java.picocli.command' });
    expectHandler(idx, imp, 'ImportCmd.call(0)');
    const reset = entry(idx, 'cli:reset-password');
    expect(reset).toMatchObject({ framework: 'spring-shell', pathTemplate: 'reset-password', ruleId: 'java.shell.command' });
    expectHandler(idx, reset, 'ShellCommands.reset(1)');
    expect(entry(idx, 'cli:admin purge').framework).toBe('spring-shell');
    expectHandler(idx, entry(idx, 'cli:Startup'), 'Startup.run(1)');
  });
});

describe('Kotlin non-HTTP entries', () => {
  it('listeners, schedules, sockets, STOMP, Thrift / Dubbo and commands', async () => {
    const idx = await indexOf({
      'src/main/kotlin/shop/Consumers.kt': `package shop

import org.springframework.kafka.annotation.KafkaListener

@Component
class Consumers(private val repo: Repo) {
    @KafkaListener(topics = ["orders"], groupId = "g")
    @PreAuthorize("hasRole('SYSTEM')")
    fun onOrder(msg: String) { }

    @RabbitListener(queues = ["\\\${app.queue}"])
    fun onQueue(msg: String) { }

    @Scheduled(cron = "0 */5 * * * *")
    fun every5() { }

    fun plain() { }
}
`,
      'src/main/kotlin/shop/Sockets.kt': `package shop

@ServerEndpoint("/ws/kt")
class KtEndpoint {
    @OnMessage
    fun message(text: String) { }
}

@Configuration
class KtWsConfig : WebSocketConfigurer {
    override fun registerWebSocketHandlers(registry: WebSocketHandlerRegistry) {
        registry.addHandler(KtHandler(), "/kt-echo")
    }
}

class KtHandler : TextWebSocketHandler() {
    override fun handleTextMessage(session: WebSocketSession, message: TextMessage) { }
}

@Controller
@MessageMapping("chat")
class KtStomp {
    @MessageMapping("send")
    fun send(msg: String) { }
}
`,
      'src/main/kotlin/shop/Rpc.kt': `package shop

import org.apache.dubbo.config.annotation.DubboService

class KtUserService : UserService.Iface {
    override fun getUser(id: Long): User = TODO()
    private fun audit() { }
}

@DubboService
class KtOrderFacade : OrderFacade {
    override fun find(id: String): Order? = null
    internal fun hidden() { }
}

@Service
class KtPlain : OrderApi {
    fun get(id: String) = id
}
`,
      'src/main/kotlin/tool/Cli.kt': `package tool

import picocli.CommandLine.Command

@Command(name = "export")
class ExportCmd : Runnable {
    override fun run() { }
}
`,
    });
    expect(channelKeys(idx)).toEqual([
      'cli:export', 'cron:Consumers.every5', 'mq:kafka:orders', 'mq:rabbitmq:${app.queue}', 'rpc:dubbo:OrderFacade/find', 'rpc:thrift:UserService/getUser',
      'stomp:chat/send', 'ws:/kt-echo', 'ws:/ws/kt',
    ]);
    const order = entry(idx, 'mq:kafka:orders');
    expect(order).toMatchObject({ kind: 'message', protocol: 'kafka', framework: 'spring-kafka', pathTemplate: 'orders', ruleId: 'kotlin.kafka.listener' });
    expect(order.authSignals).toEqual(['@PreAuthorize("hasRole(\'SYSTEM\')")']);
    expectHandler(idx, order, 'Consumers.onOrder(1)');
    expect(entry(idx, 'mq:rabbitmq:${app.queue}').pathTemplate).toBe('${app.queue}');
    expect(entry(idx, 'cron:Consumers.every5')).toMatchObject({ kind: 'schedule', protocol: 'cron', pathTemplate: '0 */5 * * * *' });
    expectHandler(idx, entry(idx, 'ws:/ws/kt'), 'KtEndpoint.message(1)');
    expectHandler(idx, entry(idx, 'ws:/kt-echo'), 'KtHandler.handleTextMessage(2)');
    expect(entry(idx, 'stomp:chat/send')).toMatchObject({ protocol: 'stomp', pathTemplate: 'chat/send' });
    expectHandler(idx, entry(idx, 'rpc:thrift:UserService/getUser'), 'KtUserService.getUser(1)');
    expect(entry(idx, 'rpc:dubbo:OrderFacade/find')).toMatchObject({ kind: 'rpc', protocol: 'dubbo', framework: 'dubbo' });
    expect(entry(idx, 'cli:export')).toMatchObject({ kind: 'cli', framework: 'picocli', pathTemplate: 'export', ruleId: 'kotlin.picocli.command' });
    expectHandler(idx, entry(idx, 'cli:export'), 'ExportCmd.run(0)');
  });
});
