// PHP entries that are not HTTP routes — WebSocket servers / broadcast channels, queue consumers (Laravel jobs,
// Symfony Messenger, php-amqplib), schedules (Laravel scheduler, Symfony Scheduler) and console commands (Artisan,
// Symfony Console). Inline sources, never executed.
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { createSnapshot, Executor, SnapshotView, buildIndex, loadRules } from '@xiezhi/context';
import type { StructIndex } from '@xiezhi/contracts';

async function indexOf(files: Record<string, string>): Promise<StructIndex> {
  const root = mkdtempSync(join(tmpdir(), 'ca-m10php-'));
  const src = join(root, 'repo');
  for (const [p, c] of Object.entries(files)) { mkdirSync(dirname(join(src, p)), { recursive: true }); writeFileSync(join(src, p), c); }
  const ex = new Executor({ scratchDir: join(root, 'exec') });
  const s = await createSnapshot({ source: { kind: 'local', path: src }, snapshotsDir: join(root, 'snapshots'), tmpDir: join(root, 'tmp'), executor: ex });
  const view = new SnapshotView('repo', s.root, s.manifest);
  return (await buildIndex(view, loadRules(), { indexesDir: join(root, 'indexes') })).index;
}

const byKey = (idx: StructIndex, k: string) => {
  const e = idx.entrypoints.find((x) => x.entryKey === k);
  if (!e) throw new Error(`no entry ${k}; have ${idx.entrypoints.map((x) => x.entryKey).join(', ')}`);
  return e;
};
const shape = (idx: StructIndex, k: string) => {
  const e = byKey(idx, k);
  return { kind: e.kind, protocol: e.protocol, route: e.pathTemplate, framework: e.framework, ruleId: e.ruleId, httpMethod: e.httpMethod };
};
const handlerName = (idx: StructIndex, k: string) => idx.symbols.find((s) => s.symbolId === byKey(idx, k).handler)?.name ?? byKey(idx, k).handler;

const COMPOSER = JSON.stringify({ require: { 'laravel/framework': '^11.0' } });

describe('PHP non-HTTP entries', () => {
  it('WebSocket: Ratchet component, Swoole server, Workerman worker, Laravel broadcast channel', async () => {
    const idx = await indexOf({
      'composer.json': COMPOSER,
      'src/Chat.php': `<?php
namespace App;
use Ratchet\\MessageComponentInterface;
use Ratchet\\ConnectionInterface;
class Chat implements MessageComponentInterface {
    public function onOpen(ConnectionInterface $conn) {}
    public function onMessage(ConnectionInterface $from, $msg) { $this->broadcast($msg); }
    public function onClose(ConnectionInterface $conn) {}
    public function onError(ConnectionInterface $conn, \\Exception $e) {}
    private function broadcast($m) {}
}
`,
      'bin/swoole.php': `<?php
use Swoole\\WebSocket\\Server;
$server = new Server('0.0.0.0', 9502);
$server->on('open', function ($server, $req) {});
$server->on('message', function ($server, $frame) { handle_frame($frame->data); });
$server->start();
`,
      'bin/worker.php': `<?php
use Workerman\\Worker;
$ws = new Worker('websocket://0.0.0.0:2346');
$ws->onMessage = function ($connection, $data) { $connection->send($data); };
$http = new Worker('http://0.0.0.0:8080');
Worker::runAll();
`,
      'routes/channels.php': `<?php
use Illuminate\\Support\\Facades\\Broadcast;
use App\\Broadcasting\\OrderChannel;
Broadcast::channel('orders.{orderId}', function ($user, $orderId) { return $user->id === $orderId; });
Broadcast::channel('shipments.{id}', OrderChannel::class);
`,
      'app/Broadcasting/OrderChannel.php': `<?php
namespace App\\Broadcasting;
class OrderChannel { public function join($user, $id) { return true; } }
`,
    });
    expect(shape(idx, 'ws:Chat')).toEqual({ kind: 'socket', protocol: 'websocket', route: 'Chat', framework: 'ratchet', ruleId: 'php.ratchet.component', httpMethod: undefined });
    expect(handlerName(idx, 'ws:Chat')).toBe('onMessage');

    expect(shape(idx, 'ws:0.0.0.0:9502')).toMatchObject({ kind: 'socket', protocol: 'websocket', route: '0.0.0.0:9502', framework: 'swoole', ruleId: 'php.swoole.websocket' });
    expect(handlerName(idx, 'ws:0.0.0.0:9502')).toBe('<main>');
    expect(idx.entrypoints.filter((e) => e.ruleId === 'php.swoole.websocket')).toHaveLength(1);

    expect(shape(idx, 'ws:0.0.0.0:2346')).toMatchObject({ kind: 'socket', protocol: 'websocket', route: '0.0.0.0:2346', framework: 'workerman', ruleId: 'php.workerman.websocket' });
    expect(idx.entrypoints.filter((e) => e.ruleId === 'php.workerman.websocket')).toHaveLength(1); // the http:// worker is not a socket

    expect(shape(idx, 'ws:orders.{orderId}')).toMatchObject({ kind: 'socket', protocol: 'broadcast', route: 'orders.{orderId}', framework: 'laravel', ruleId: 'php.laravel.broadcast' });
    expect(handlerName(idx, 'ws:orders.{orderId}')).toBe('<main>');
    expect(handlerName(idx, 'ws:shipments.{id}')).toBe('join');

    // Server scripts without request superglobals stay out of the HTTP table.
    expect(idx.entrypoints.filter((e) => e.kind === 'http')).toEqual([]);
  });

  it('queues: Laravel jobs and queued listeners, Symfony Messenger handlers, php-amqplib consumers', async () => {
    const idx = await indexOf({
      'composer.json': COMPOSER,
      'app/Jobs/ProcessPodcast.php': `<?php
namespace App\\Jobs;
use Illuminate\\Contracts\\Queue\\ShouldQueue;
use Illuminate\\Foundation\\Queue\\Queueable;
class ProcessPodcast implements ShouldQueue {
    use Queueable;
    public function __construct(public int $podcastId) {}
    public function handle(): void { exec("ffmpeg -i " . $this->podcastId); }
}
`,
      'app/Listeners/SendShipmentNotification.php': `<?php
namespace App\\Listeners;
use App\\Events\\OrderShipped;
use Illuminate\\Contracts\\Queue\\ShouldQueue;
class SendShipmentNotification implements ShouldQueue {
    public function handle(OrderShipped $event): void {}
}
`,
      'app/Mail/Invoice.php': `<?php
namespace App\\Mail;
use Illuminate\\Contracts\\Queue\\ShouldQueue;
class Invoice extends Mailable implements ShouldQueue { public function build() { return $this; } }
`,
      'src/MessageHandler/SmsHandler.php': `<?php
namespace App\\MessageHandler;
use App\\Message\\SmsNotification;
use Symfony\\Component\\Messenger\\Attribute\\AsMessageHandler;
#[AsMessageHandler]
class SmsHandler {
    public function __invoke(SmsNotification $message) {}
}
`,
      'src/MessageHandler/LegacyHandler.php': `<?php
namespace App\\MessageHandler;
use Symfony\\Component\\Messenger\\Handler\\MessageHandlerInterface;
class LegacyHandler implements MessageHandlerInterface {
    public function __invoke(ResizeImage $m) {}
}
`,
      'src/MessageHandler/MultiHandler.php': `<?php
namespace App\\MessageHandler;
use Symfony\\Component\\Messenger\\Attribute\\AsMessageHandler;
class MultiHandler {
    #[AsMessageHandler]
    public function onCreated(UserCreated $m) {}
    #[AsMessageHandler(handles: UserDeleted::class)]
    public function onDeleted($m) {}
}
`,
      'bin/consumer.php': `<?php
use PhpAmqpLib\\Connection\\AMQPStreamConnection;
$connection = new AMQPStreamConnection('localhost', 5672, 'guest', 'guest');
$channel = $connection->channel();
$channel->queue_declare('task_queue', false, true, false, false);
$callback = function ($msg) { system($msg->body); };
$channel->basic_consume('task_queue', '', false, false, false, false, $callback);
while ($channel->is_consuming()) { $channel->wait(); }
`,
    });
    expect(shape(idx, 'mq:laravel-queue:ProcessPodcast')).toMatchObject({ kind: 'message', protocol: 'laravel-queue', route: 'ProcessPodcast', framework: 'laravel', ruleId: 'php.laravel.job' });
    expect(handlerName(idx, 'mq:laravel-queue:ProcessPodcast')).toBe('handle');
    expect(handlerName(idx, 'mq:laravel-queue:SendShipmentNotification')).toBe('handle');
    expect(idx.entrypoints.some((e) => e.entryKey === 'mq:laravel-queue:Invoice')).toBe(false); // no handle(): a queued mailable

    expect(shape(idx, 'mq:symfony-messenger:SmsNotification')).toMatchObject({ kind: 'message', protocol: 'symfony-messenger', route: 'SmsNotification', framework: 'symfony', ruleId: 'php.symfony.messenger' });
    expect(handlerName(idx, 'mq:symfony-messenger:SmsNotification')).toBe('__invoke');
    expect(handlerName(idx, 'mq:symfony-messenger:ResizeImage')).toBe('__invoke');
    expect(handlerName(idx, 'mq:symfony-messenger:UserCreated')).toBe('onCreated');
    expect(handlerName(idx, 'mq:symfony-messenger:UserDeleted')).toBe('onDeleted');

    expect(shape(idx, 'mq:rabbitmq:task_queue')).toMatchObject({ kind: 'message', protocol: 'rabbitmq', route: 'task_queue', framework: 'php-amqplib', ruleId: 'php.amqp.consume' });
    expect(handlerName(idx, 'mq:rabbitmq:task_queue')).toBe('<main>');
    expect(idx.entrypoints.filter((e) => e.kind === 'http')).toEqual([]);
  });

  it('schedules: Laravel Kernel / routes/console.php and Symfony #[AsCronTask] / #[AsPeriodicTask]', async () => {
    const idx = await indexOf({
      'composer.json': COMPOSER,
      'app/Console/Kernel.php': `<?php
namespace App\\Console;
use App\\Jobs\\PruneUsers;
use Illuminate\\Console\\Scheduling\\Schedule;
use Illuminate\\Foundation\\Console\\Kernel as ConsoleKernel;
class Kernel extends ConsoleKernel {
    protected function schedule(Schedule $schedule): void {
        $schedule->command('emails:send --force')->dailyAt('13:00')->withoutOverlapping();
        $schedule->job(new PruneUsers)->hourly();
        $schedule->call(function () { cleanup(); })->name('cleanup-tmp')->everyFiveMinutes();
        $schedule->exec('node /home/forge/script.js')->cron('0 3 * * *');
    }
}
`,
      'app/Jobs/PruneUsers.php': `<?php
namespace App\\Jobs;
use Illuminate\\Contracts\\Queue\\ShouldQueue;
class PruneUsers implements ShouldQueue { public function handle() {} }
`,
      'routes/console.php': `<?php
use Illuminate\\Support\\Facades\\Schedule;
use Illuminate\\Support\\Facades\\Artisan;
Schedule::command('reports:build')->weekly();
Artisan::command('inspire {name?}', function ($name = null) { $this->comment($name); });
`,
      'src/Scheduler/Nightly.php': `<?php
namespace App\\Scheduler;
use Symfony\\Component\\Scheduler\\Attribute\\AsCronTask;
use Symfony\\Component\\Scheduler\\Attribute\\AsPeriodicTask;
#[AsCronTask('0 2 * * *')]
class Nightly { public function __invoke() {} }
#[AsPeriodicTask(frequency: '1 hour', method: 'refresh')]
class Feeds { public function refresh() {} }
`,
    });
    expect(shape(idx, 'cron:emails:send')).toMatchObject({ kind: 'schedule', protocol: 'cron', route: "dailyAt('13:00')", framework: 'laravel', ruleId: 'php.laravel.schedule' });
    expect(handlerName(idx, 'cron:emails:send')).toBe('schedule');
    expect(shape(idx, 'cron:PruneUsers')).toMatchObject({ kind: 'schedule', route: 'hourly()' });
    expect(handlerName(idx, 'cron:PruneUsers')).toBe('handle');
    expect(shape(idx, 'cron:cleanup-tmp')).toMatchObject({ route: 'everyFiveMinutes()' });
    expect(shape(idx, 'cron:node /home/forge/script.js')).toMatchObject({ route: '0 3 * * *' });
    expect(shape(idx, 'cron:reports:build')).toMatchObject({ kind: 'schedule', route: 'weekly()', framework: 'laravel' });
    expect(handlerName(idx, 'cron:reports:build')).toBe('<main>');

    expect(shape(idx, 'cron:Nightly')).toMatchObject({ kind: 'schedule', protocol: 'cron', route: '0 2 * * *', framework: 'symfony', ruleId: 'php.symfony.cron' });
    expect(handlerName(idx, 'cron:Nightly')).toBe('__invoke');
    expect(shape(idx, 'cron:Feeds.refresh')).toMatchObject({ route: '1 hour' });
    expect(handlerName(idx, 'cron:Feeds.refresh')).toBe('refresh');

    expect(shape(idx, 'cli:inspire')).toMatchObject({ kind: 'cli', protocol: 'cli', route: 'inspire', framework: 'laravel', ruleId: 'php.laravel.command' });
    expect(handlerName(idx, 'cli:inspire')).toBe('<main>');
    expect(idx.entrypoints.filter((e) => e.kind === 'http')).toEqual([]);
  });

  it('commands: Laravel Artisan classes and Symfony Console (#[AsCommand], $defaultName, setName)', async () => {
    const idx = await indexOf({
      'composer.json': COMPOSER,
      'app/Console/Commands/SendEmails.php': `<?php
namespace App\\Console\\Commands;
use Illuminate\\Console\\Command;
class SendEmails extends Command {
    protected $signature = 'mail:send {user} {--queue}';
    protected $description = 'Send a marketing email';
    public function handle(): void { shell_exec('mail ' . $this->argument('user')); }
}
`,
      'src/Command/CreateUser.php': `<?php
namespace App\\Command;
use Symfony\\Component\\Console\\Attribute\\AsCommand;
use Symfony\\Component\\Console\\Command\\Command;
#[AsCommand(name: 'app:create-user|app:add-user', description: 'Creates a user')]
class CreateUser extends Command {
    protected function execute(InputInterface $input, OutputInterface $output): int { return 0; }
}
`,
      'src/Command/Legacy.php': `<?php
namespace App\\Command;
use Symfony\\Component\\Console\\Command\\Command;
class Legacy extends Command {
    protected static $defaultName = 'app:legacy';
    protected function execute($input, $output): int { return 0; }
}
`,
      'src/Command/Configured.php': `<?php
namespace App\\Command;
use Symfony\\Component\\Console\\Command\\Command;
class Configured extends Command {
    protected function configure(): void { $this->setName('app:configured')->setDescription('x'); }
    protected function execute($input, $output): int { return 0; }
}
`,
      // Negatives: a command base class without a name, a plain CLI script reading $argv, a class file.
      'app/Console/Commands/BaseCommand.php': `<?php
namespace App\\Console\\Commands;
use Illuminate\\Console\\Command;
abstract class BaseCommand extends Command { public function handle() {} }
`,
      'scripts/import.php': `<?php
$file = $argv[1] ?? 'data.csv';
foreach (file($file) as $line) { echo $line; }
`,
      'src/Service/Mailer.php': `<?php
namespace App\\Service;
class Mailer { public function onMessage($m) {} public function handle() {} }
`,
    });
    expect(shape(idx, 'cli:mail:send')).toEqual({ kind: 'cli', protocol: 'cli', route: 'mail:send', framework: 'laravel', ruleId: 'php.laravel.command', httpMethod: undefined });
    expect(handlerName(idx, 'cli:mail:send')).toBe('handle');
    expect(shape(idx, 'cli:app:create-user')).toMatchObject({ kind: 'cli', protocol: 'cli', route: 'app:create-user', framework: 'symfony', ruleId: 'php.symfony.command' });
    expect(handlerName(idx, 'cli:app:create-user')).toBe('execute');
    expect(handlerName(idx, 'cli:app:legacy')).toBe('execute');
    expect(handlerName(idx, 'cli:app:configured')).toBe('execute');
    expect(idx.entrypoints.map((e) => e.entryKey).sort()).toEqual(['cli:app:configured', 'cli:app:create-user', 'cli:app:legacy', 'cli:mail:send']);
  });

  it('native HTTP scripts keep their file-level entry next to a socket in the same repository', async () => {
    const idx = await indexOf({
      'public/search.php': `<?php
$q = $_GET['q'];
echo htmlspecialchars($q);
`,
      'src/Chat.php': `<?php
use Ratchet\\MessageComponentInterface;
class Chat implements MessageComponentInterface { public function onMessage($from, $msg) {} }
`,
    });
    expect(shape(idx, 'ANY /search.php')).toMatchObject({ kind: 'http', framework: 'php', ruleId: 'php.native.script', httpMethod: 'ANY', route: '/search.php' });
    expect(idx.entrypoints.map((e) => e.entryKey).sort()).toEqual(['ANY /search.php', 'ws:Chat']);
  });
});
