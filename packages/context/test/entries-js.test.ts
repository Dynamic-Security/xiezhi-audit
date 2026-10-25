// JavaScript / TypeScript non-HTTP entries: WebSocket / Socket.IO, NestJS gateways / microservices / schedules,
// Kafka / RabbitMQ / BullMQ / Redis consumers, cron jobs and CLI commands, on small inline sources (never executed).
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { describe, expect, it } from 'vitest';
import type { StructIndex } from '@xiezhi/contracts';
import { Executor, SnapshotView, buildIndex, createSnapshot, loadRules } from '@xiezhi/context';

// `express` marks the repository as a JS backend; the other packages gate the recognizers.
const PKG = (deps: string[]) => JSON.stringify({ name: 't', dependencies: Object.fromEntries(['express', ...deps].map((d) => [d, '1'])) });

async function indexOf(files: Record<string, string>): Promise<StructIndex> {
  const root = mkdtempSync(join(tmpdir(), 'ca-m10js-'));
  const src = join(root, 'repo');
  for (const [p, c] of Object.entries(files)) { mkdirSync(dirname(join(src, p)), { recursive: true }); writeFileSync(join(src, p), c); }
  const ex = new Executor({ scratchDir: join(root, 'exec') });
  const s = await createSnapshot({ source: { kind: 'local', path: src }, snapshotsDir: join(root, 'snapshots'), tmpDir: join(root, 'tmp'), executor: ex });
  const v = new SnapshotView('repo', s.root, s.manifest);
  return (await buildIndex(v, loadRules(), { indexesDir: join(root, 'indexes') })).index;
}

const channelKeys = (idx: StructIndex) => idx.entrypoints.filter((e) => e.kind !== 'http').map((e) => e.entryKey).sort();
const entry = (idx: StructIndex, key: string) => {
  const e = idx.entrypoints.find((x) => x.entryKey === key);
  if (!e) throw new Error(`no entry ${key}; have ${idx.entrypoints.map((x) => x.entryKey).join(', ')}`);
  return e;
};

describe('JS sockets', () => {
  it('Socket.IO events in connection handlers, namespaces, local register functions and io.use middlewares', async () => {
    const idx = await indexOf({
      'package.json': PKG(['socket.io']),
      'src/io.js': `const { Server } = require('socket.io');
const io = new Server(3000);
io.use(authenticateSocket);
const chat = io.of('/chat');
io.on('connection', (socket) => {
  socket.on('message', (msg) => broadcast(msg));
  socket.on('join', onJoin);
  socket.on('disconnect', () => {});
  registerAdmin(io, socket);
});
chat.on('connection', (s) => { s.on('send', handleSend); });
function registerAdmin(server, sock) { sock.on('admin:kick', (id) => kick(id)); }
function onJoin(room) {}
function handleSend(m) {}
function authenticateSocket(socket, next) { next(); }
function broadcast(m) {}
function kick(id) {}
`,
    });
    expect(channelKeys(idx)).toEqual(['socketio:/chat#send', 'socketio:admin:kick', 'socketio:join', 'socketio:message']);
    const msg = entry(idx, 'socketio:message');
    expect(msg).toMatchObject({ kind: 'socket', protocol: 'socketio', pathTemplate: 'message', framework: 'socket.io', ruleId: 'js.socketio.event' });
    expect(msg.handler).toMatch(/#src\/io\.<anonymous socketio message>\(1\)$/);
    expect(msg.httpMethod).toBeUndefined();
    expect(msg.middlewares).toEqual(['authenticateSocket']);
    expect(msg.authSignals).toEqual(['authenticateSocket']);
    expect(entry(idx, 'socketio:join').handler).toBe('repo:src/io.js#src/io.onJoin(1)');
    const send = entry(idx, 'socketio:/chat#send');
    expect(send).toMatchObject({ pathTemplate: '/chat#send', handler: 'repo:src/io.js#src/io.handleSend(1)', middlewares: [] });
    expect(entry(idx, 'socketio:admin:kick').handler).toMatch(/<anonymous socketio admin:kick>/);
  });

  it('an EventEmitter that is not Socket.IO produces no entries', async () => {
    const idx = await indexOf({
      'package.json': PKG([]),
      'src/events.js': `const EventEmitter = require('events');
const emitter = new EventEmitter();
emitter.on('connection', (socket) => { socket.on('message', (m) => console.log(m)); });
emitter.on('x', () => {});
`,
    });
    expect(channelKeys(idx)).toEqual([]);
  });

  it('ws servers (path or variable name), express-ws routes, uWebSockets.js and @fastify/websocket', async () => {
    const idx = await indexOf({
      'package.json': PKG(['ws', 'express-ws', 'uWebSockets.js', 'fastify', '@fastify/websocket']),
      'src/ws.ts': `import { WebSocketServer } from 'ws';
import WebSocket from 'ws';
const wss = new WebSocketServer({ port: 8080, path: '/live' });
const feed = new WebSocket.Server({ noServer: true });
wss.on('connection', onLive);
feed.on('connection', (ws) => { ws.on('message', (d) => ws.send(d)); });
function onLive(ws: WebSocket) {}
`,
      'src/ews.js': `const express = require('express');
const expressWs = require('express-ws');
const app = express();
expressWs(app);
const router = express.Router();
router.ws('/echo', requireAuth, (ws, req) => { ws.on('message', (m) => ws.send(m)); });
app.use('/sock', router);
function requireAuth(ws, req, next) { next(); }
`,
      'src/uws.js': `const uWS = require('uWebSockets.js');
uWS.App().ws('/stream/*', { compression: 0, message: (ws, message, isBinary) => { ws.send(message); } }).listen(9001, () => {});
`,
      'src/fws.js': `const fastify = require('fastify')();
fastify.register(require('@fastify/websocket'));
fastify.get('/chat', { websocket: true }, (connection, req) => { connection.socket.on('message', () => {}); });
`,
    });
    expect(channelKeys(idx)).toEqual(['ws:/chat', 'ws:/live', 'ws:/sock/echo', 'ws:/stream/*', 'ws:feed']);
    expect(entry(idx, 'ws:/live')).toMatchObject({ kind: 'socket', protocol: 'websocket', pathTemplate: '/live', framework: 'ws', ruleId: 'js.ws.server', handler: 'repo:src/ws.ts#src/ws.onLive(1)' });
    expect(entry(idx, 'ws:feed')).toMatchObject({ pathTemplate: 'feed', framework: 'ws' });
    expect(entry(idx, 'ws:feed').handler).toMatch(/<anonymous websocket feed>\(1\)$/);
    const echo = entry(idx, 'ws:/sock/echo');
    expect(echo).toMatchObject({ framework: 'express-ws', ruleId: 'js.express-ws.route', pathTemplate: '/sock/echo', middlewares: ['requireAuth'], authSignals: ['requireAuth'] });
    expect(echo.handler).toMatch(/<anonymous websocket \/sock\/echo>\(2\)$/);
    expect(entry(idx, 'ws:/stream/*')).toMatchObject({ framework: 'uWebSockets.js', ruleId: 'js.uws.ws', pathTemplate: '/stream/*' });
    expect(entry(idx, 'ws:/stream/*').handler).toMatch(/<anonymous websocket \/stream\/\*>\(3\)$/);
    expect(entry(idx, 'ws:/chat')).toMatchObject({ framework: 'fastify-websocket', ruleId: 'js.fastify.websocket' });
    // the HTTP entry of the fastify upgrade route stays
    expect(entry(idx, 'GET /chat').kind).toBe('http');
  });
});

describe('NestJS', () => {
  it('gateways (namespace, guards), microservice patterns with transports, @Cron / @Interval and bull processors', async () => {
    const idx = await indexOf({
      'package.json': PKG(['@nestjs/core', '@nestjs/websockets', '@nestjs/microservices', '@nestjs/schedule', '@nestjs/bullmq']),
      'src/chat.gateway.ts': `import { SubscribeMessage, WebSocketGateway, MessageBody } from '@nestjs/websockets';
import { UseGuards } from '@nestjs/common';
@WebSocketGateway(81, { namespace: 'chat' })
@UseGuards(WsJwtGuard)
export class ChatGateway {
  @SubscribeMessage('message')
  handleMessage(@MessageBody() data: string) { return data; }
  @SubscribeMessage('events')
  @UseGuards(AdminGuard)
  handleEvents(client: any, data: any) { return data; }
}
`,
      'src/orders.controller.ts': `import { Controller } from '@nestjs/common';
import { MessagePattern, EventPattern, Payload, Ctx, KafkaContext, Transport } from '@nestjs/microservices';
@Controller()
export class OrdersController {
  @MessagePattern({ cmd: 'get_order' })
  getOrder(@Payload() id: number) { return id; }
  @EventPattern('order_created', Transport.RMQ)
  onCreated(data: any) {}
  @MessagePattern('payments')
  onPayment(@Payload() msg: any, @Ctx() context: KafkaContext) {}
}
`,
      'src/tasks.service.ts': `import { Injectable } from '@nestjs/common';
import { Cron, CronExpression, Interval } from '@nestjs/schedule';
@Injectable()
export class TasksService {
  @Cron('45 * * * * *')
  handleCron() {}
  @Cron(CronExpression.EVERY_HOUR)
  hourly() {}
  @Interval(10000)
  poll() {}
}
`,
      'src/mail.processor.ts': `import { Processor, WorkerHost } from '@nestjs/bullmq';
@Processor('mail')
export class MailProcessor extends WorkerHost {
  async process(job: any) { return job.data; }
}
`,
    });
    expect(channelKeys(idx)).toEqual([
      'cron:TasksService.handleCron', 'cron:TasksService.hourly', 'cron:TasksService.poll',
      'mq:bullmq:mail', 'mq:kafka:payments', 'mq:nest-microservice:cmd:get_order', 'mq:rabbitmq:order_created',
      'socketio:/chat#events', 'socketio:/chat#message',
    ]);
    const msg = entry(idx, 'socketio:/chat#message');
    expect(msg).toMatchObject({ kind: 'socket', protocol: 'socketio', framework: 'nestjs', ruleId: 'js.nest.gateway', pathTemplate: '/chat#message', handler: 'repo:src/chat.gateway.ts#src/chat.gateway.ChatGateway.handleMessage(1)' });
    expect(msg.authSignals).toEqual(['@UseGuards(WsJwtGuard)']);
    expect(entry(idx, 'socketio:/chat#events').authSignals).toEqual(['@UseGuards(WsJwtGuard)', '@UseGuards(AdminGuard)']);
    expect(entry(idx, 'mq:nest-microservice:cmd:get_order')).toMatchObject({ kind: 'message', protocol: 'nest-microservice', pathTemplate: 'cmd:get_order', ruleId: 'js.nest.microservice', handler: 'repo:src/orders.controller.ts#src/orders.controller.OrdersController.getOrder(1)' });
    expect(entry(idx, 'mq:rabbitmq:order_created').protocol).toBe('rabbitmq');
    expect(entry(idx, 'mq:kafka:payments').protocol).toBe('kafka');
    expect(entry(idx, 'cron:TasksService.handleCron')).toMatchObject({ kind: 'schedule', protocol: 'cron', pathTemplate: '45 * * * * *', framework: 'nestjs', handler: 'repo:src/tasks.service.ts#src/tasks.service.TasksService.handleCron(0)' });
    expect(entry(idx, 'cron:TasksService.hourly').pathTemplate).toBe('CronExpression.EVERY_HOUR');
    expect(entry(idx, 'cron:TasksService.poll')).toMatchObject({ protocol: 'interval', pathTemplate: '10000ms' });
    expect(entry(idx, 'mq:bullmq:mail')).toMatchObject({ kind: 'message', protocol: 'bullmq', handler: 'repo:src/mail.processor.ts#src/mail.processor.MailProcessor.process(1)' });
  });

  it('a gateway on the ws adapter is a websocket entry', async () => {
    const idx = await indexOf({
      'package.json': PKG(['@nestjs/core', '@nestjs/websockets', '@nestjs/platform-ws']),
      'src/events.gateway.ts': `import { SubscribeMessage, WebSocketGateway } from '@nestjs/websockets';
import { WsAdapter } from '@nestjs/platform-ws';
@WebSocketGateway({ path: '/events' })
export class EventsGateway {
  @SubscribeMessage('ping')
  ping() { return 'pong'; }
}
`,
    });
    expect(channelKeys(idx)).toEqual(['ws:/events#ping']);
    expect(entry(idx, 'ws:/events#ping')).toMatchObject({ kind: 'socket', protocol: 'websocket', framework: 'nestjs' });
  });
});

describe('message consumers', () => {
  it('kafkajs, amqplib, bullmq / bull and redis subscribers', async () => {
    const idx = await indexOf({
      'package.json': PKG(['kafkajs', 'amqplib', 'bullmq', 'bull', 'redis', 'ioredis']),
      'src/kafka.ts': `import { Kafka } from 'kafkajs';
const kafka = new Kafka({ brokers: ['k:9092'] });
const consumer = kafka.consumer({ groupId: 'g' });
export async function start() {
  await consumer.subscribe({ topic: 'orders', fromBeginning: true });
  await consumer.subscribe({ topics: ['refunds', /audit\\..*/] });
  await consumer.run({ eachMessage: handleOrder });
}
async function handleOrder({ topic, message }: any) {}
`,
      'src/amqp.js': `const amqp = require('amqplib');
async function main() {
  const ch = await (await amqp.connect('amqp://x')).createChannel();
  const q = 'tasks';
  ch.consume(q, (msg) => { work(msg.content.toString()); });
  ch.consume('emails', sendEmail, { noAck: true });
}
function sendEmail(msg) {}
function work(s) {}
`,
      'src/jobs.ts': `import { Worker } from 'bullmq';
new Worker('reports', async (job) => { return build(job.data); }, { connection: {} });
new Worker('thumbs', './thumb-processor.js');
function build(d: any) {}
`,
      'src/legacy-queue.js': `const Queue = require('bull');
const imageQueue = new Queue('images', 'redis://x');
imageQueue.process('resize', 5, resizeImage);
imageQueue.process(async (job) => {});
function resizeImage(job) {}
`,
      'src/pubsub.ts': `import { createClient } from 'redis';
const sub = createClient().duplicate();
await sub.subscribe('notifications', (message) => notify(message));
function notify(m: string) {}
`,
      'src/io-pubsub.js': `const Redis = require('ioredis');
const r = new Redis();
r.subscribe('chat', 'alerts', (err, count) => {});
r.on('message', onMessage);
function onMessage(channel, message) {}
`,
    });
    expect(channelKeys(idx)).toEqual([
      'mq:bullmq:images', 'mq:bullmq:images/resize', 'mq:bullmq:reports', 'mq:bullmq:thumbs',
      'mq:kafka:/audit\\..*/', 'mq:kafka:orders', 'mq:kafka:refunds',
      'mq:rabbitmq:emails', 'mq:rabbitmq:tasks',
      'mq:redis:alerts', 'mq:redis:chat', 'mq:redis:notifications',
    ]);
    expect(entry(idx, 'mq:kafka:orders')).toMatchObject({ kind: 'message', protocol: 'kafka', pathTemplate: 'orders', framework: 'kafkajs', ruleId: 'js.kafkajs.consumer', handler: 'repo:src/kafka.ts#src/kafka.handleOrder(1)' });
    expect(entry(idx, 'mq:rabbitmq:tasks')).toMatchObject({ protocol: 'rabbitmq', framework: 'amqplib', ruleId: 'js.amqp.consume' });
    expect(entry(idx, 'mq:rabbitmq:tasks').handler).toMatch(/<anonymous rabbitmq tasks>\(1\)$/);
    expect(entry(idx, 'mq:rabbitmq:emails').handler).toBe('repo:src/amqp.js#src/amqp.sendEmail(1)');
    expect(entry(idx, 'mq:bullmq:reports')).toMatchObject({ protocol: 'bullmq', framework: 'bullmq', ruleId: 'js.bullmq.worker' });
    expect(entry(idx, 'mq:bullmq:reports').handler).toMatch(/<anonymous bullmq reports>\(1\)$/);
    expect(entry(idx, 'mq:bullmq:thumbs').handler).toMatch(/<unresolved:anonymous>$/);
    expect(entry(idx, 'mq:bullmq:images/resize')).toMatchObject({ framework: 'bull', ruleId: 'js.bull.process', pathTemplate: 'images/resize', handler: 'repo:src/legacy-queue.js#src/legacy-queue.resizeImage(1)' });
    expect(entry(idx, 'mq:redis:notifications')).toMatchObject({ protocol: 'redis', framework: 'redis', ruleId: 'js.redis.subscribe' });
    expect(entry(idx, 'mq:redis:notifications').handler).toMatch(/<anonymous redis notifications>\(1\)$/);
    // ioredis: the `message` listener, not the subscribe completion callback
    expect(entry(idx, 'mq:redis:chat').handler).toBe('repo:src/io-pubsub.js#src/io-pubsub.onMessage(2)');
  });
});

describe('schedules and commands', () => {
  it('node-cron, cron CronJob, node-schedule', async () => {
    const idx = await indexOf({
      'package.json': PKG(['node-cron', 'cron', 'node-schedule']),
      'src/cron.js': `const cron = require('node-cron');
const { CronJob } = require('cron');
const schedule = require('node-schedule');
cron.schedule('0 3 * * *', cleanupSessions);
cron.schedule('*/5 * * * *', () => { ping(); });
new CronJob('0 0 * * 0', weeklyReport, null, true);
CronJob.from({ cronTime: '0 12 * * *', onTick: noonDigest, start: true });
schedule.scheduleJob('nightly', '0 1 * * *', backup);
function cleanupSessions() {}
function weeklyReport() {}
function noonDigest() {}
function backup() {}
function ping() {}
`,
    });
    expect(channelKeys(idx)).toEqual(['cron:*/5 * * * *', 'cron:backup', 'cron:cleanupSessions', 'cron:noonDigest', 'cron:weeklyReport']);
    expect(entry(idx, 'cron:cleanupSessions')).toMatchObject({ kind: 'schedule', protocol: 'cron', pathTemplate: '0 3 * * *', framework: 'node-cron', ruleId: 'js.cron', handler: 'repo:src/cron.js#src/cron.cleanupSessions(0)' });
    expect(entry(idx, 'cron:*/5 * * * *').handler).toMatch(/<anonymous cron \*\/5 \* \* \* \*>\(0\)$/);
    expect(entry(idx, 'cron:weeklyReport')).toMatchObject({ framework: 'cron', pathTemplate: '0 0 * * 0' });
    expect(entry(idx, 'cron:noonDigest')).toMatchObject({ framework: 'cron', pathTemplate: '0 12 * * *' });
    expect(entry(idx, 'cron:backup')).toMatchObject({ framework: 'node-schedule', pathTemplate: '0 1 * * *' });
  });

  it('commander and yargs commands', async () => {
    const idx = await indexOf({
      'package.json': PKG(['commander', 'yargs']),
      'src/cli.ts': `import { Command } from 'commander';
const program = new Command();
program.command('import-users <file>').description('import').option('-d, --dry').action(importUsers);
const reset = program.command('reset');
reset.action(async () => { await wipe(); });
program.parse();
function importUsers(file: string) {}
async function wipe() {}
`,
      'src/y.js': `const yargs = require('yargs');
const { hideBin } = require('yargs/helpers');
yargs(hideBin(process.argv))
  .command('serve [port]', 'start the server', (y) => y.positional('port', {}), (argv) => serve(argv.port))
  .command({ command: 'migrate <dir>', describe: 'migrate', handler: runMigrations })
  .command('noop', 'builder only', (y) => y)
  .parse();
function serve(p) {}
function runMigrations(argv) {}
`,
    });
    expect(channelKeys(idx)).toEqual(['cli:import-users', 'cli:migrate', 'cli:reset', 'cli:serve']);
    expect(entry(idx, 'cli:import-users')).toMatchObject({ kind: 'cli', protocol: 'cli', pathTemplate: 'import-users', framework: 'commander', ruleId: 'js.commander.command', handler: 'repo:src/cli.ts#src/cli.importUsers(1)' });
    expect(entry(idx, 'cli:reset').handler).toMatch(/<anonymous cli reset>\(0\)$/);
    expect(entry(idx, 'cli:serve')).toMatchObject({ framework: 'yargs', ruleId: 'js.yargs.command' });
    expect(entry(idx, 'cli:serve').handler).toMatch(/<anonymous cli serve>\(1\)$/);
    expect(entry(idx, 'cli:migrate').handler).toBe('repo:src/y.js#src/y.runMigrations(1)');
  });
});
