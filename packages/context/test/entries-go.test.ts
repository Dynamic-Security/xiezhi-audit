// Go entries that are not HTTP routes — WebSocket upgrades, queue consumers, cron jobs, commands, Thrift.
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { describe, expect, it } from 'vitest';
import type { StructIndex } from '@xiezhi/contracts';
import { buildIndex, createSnapshot, Executor, loadRules, SnapshotView } from '@xiezhi/context';

async function viewOf(files: Record<string, string>): Promise<SnapshotView> {
  const root = mkdtempSync(join(tmpdir(), 'ca-m10go-'));
  const src = join(root, 'repo');
  for (const [p, c] of Object.entries(files)) { mkdirSync(dirname(join(src, p)), { recursive: true }); writeFileSync(join(src, p), c); }
  const ex = new Executor({ scratchDir: join(root, 'exec') });
  const s = await createSnapshot({ source: { kind: 'local', path: src }, snapshotsDir: join(root, 'snapshots'), tmpDir: join(root, 'tmp'), executor: ex });
  return new SnapshotView('repo', s.root, s.manifest);
}
const indexOf = async (files: Record<string, string>) =>
  (await buildIndex(await viewOf({ 'go.mod': 'module example.com/app\n\ngo 1.22\n', ...files }), loadRules(), { indexesDir: mkdtempSync(join(tmpdir(), 'ca-m10go-i-')) })).index;
const keysOf = (idx: StructIndex, kind: string) => idx.entrypoints.filter((e) => e.kind === kind).map((e) => e.entryKey).sort();
const entry = (idx: StructIndex, key: string) => {
  const e = idx.entrypoints.find((x) => x.entryKey === key);
  if (!e) throw new Error(`no entry ${key}: ${idx.entrypoints.map((x) => x.entryKey).join(', ')}`);
  return e;
};

describe('Go channel entries', () => {
  it('WebSocket: socket entries beside the HTTP route (gin, net/http with a wrapper closure, nhooyr), unrouted upgrades by function', async () => {
    const idx = await indexOf({
      'ws/gin.go': `package ws

import (
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{}

func chat(c *gin.Context) {
	conn, _ := upgrader.Upgrade(c.Writer, c.Request, nil)
	defer conn.Close()
}

func plain(c *gin.Context) { c.JSON(200, nil) }

func Routes(r *gin.Engine) {
	api := r.Group("/api", AuthRequired())
	api.GET("/chat", chat)
	api.GET("/plain", plain)
}
`,
      'hub/main.go': `package main

import (
	"net/http"
	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{}

func serveWs(hub *Hub, w http.ResponseWriter, r *http.Request) {
	conn, _ := upgrader.Upgrade(w, r, nil)
	hub.register <- conn
}

func main() {
	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) { serveWs(hub, w, r) })
}
`,
      'nh/server.go': `package nh

import (
	"net/http"
	"nhooyr.io/websocket"
)

func echo(w http.ResponseWriter, r *http.Request) {
	c, _ := websocket.Accept(w, r, nil)
	defer c.CloseNow()
}

func Mount(mux *http.ServeMux) { mux.HandleFunc("/echo", echo) }
`,
      'other/stream.go': `package other

import "github.com/gorilla/websocket"

type Streamer struct{ up websocket.Upgrader }

func (s *Streamer) Stream(w http.ResponseWriter, r *http.Request) {
	conn, _ := s.up.Upgrade(w, r, nil)
	_ = conn
}
`,
    });
    expect(keysOf(idx, 'socket')).toEqual(['ws:/api/chat', 'ws:/echo', 'ws:/ws', 'ws:Streamer.Stream']);
    // The HTTP routes stay.
    expect(entry(idx, 'GET /api/chat')).toMatchObject({ kind: 'http' });
    expect(entry(idx, 'ANY /ws')).toMatchObject({ kind: 'http' });
    const chat = entry(idx, 'ws:/api/chat');
    expect(chat).toMatchObject({ kind: 'socket', protocol: 'websocket', pathTemplate: '/api/chat', framework: 'gorilla-websocket', ruleId: 'go.websocket.upgrade', middlewares: ['AuthRequired()'] });
    expect(chat.httpMethod).toBeUndefined();
    expect(chat.handler).toMatch(/ws\/gin\.go#ws\.chat\(1\)$/);
    expect(entry(idx, 'ws:/ws').handler).toMatch(/hub\/main\.go#main\.serveWs\(3\)$/);
    expect(entry(idx, 'ws:/echo')).toMatchObject({ framework: 'nhooyr-websocket', pathTemplate: '/echo' });
    expect(entry(idx, 'ws:/echo').handler).toMatch(/nh\/server\.go#nh\.echo\(2\)$/);
    expect(entry(idx, 'ws:Streamer.Stream')).toMatchObject({ pathTemplate: 'Streamer.Stream' });
    expect(entry(idx, 'ws:Streamer.Stream').handler).toMatch(/other\/stream\.go#other\.Streamer\.Stream\(2\)$/);
  });

  it('Kafka: sarama consumer group (topics from Consume), handler in another file, partition consumer; kafka-go reader', async () => {
    const idx = await indexOf({
      'consumer/handler.go': `package consumer

import "github.com/IBM/sarama"

type orderHandler struct{}

func (orderHandler) Setup(sarama.ConsumerGroupSession) error   { return nil }
func (orderHandler) Cleanup(sarama.ConsumerGroupSession) error { return nil }
func (h orderHandler) ConsumeClaim(sess sarama.ConsumerGroupSession, claim sarama.ConsumerGroupClaim) error { return nil }
`,
      'consumer/run.go': `package consumer

import "github.com/IBM/sarama"

const auditTopic = "audit"

func Run(ctx context.Context, group sarama.ConsumerGroup, c sarama.Consumer) {
	h := &orderHandler{}
	for {
		group.Consume(ctx, []string{"orders", auditTopic}, h)
	}
	pc, _ := c.ConsumePartition("payments", 0, sarama.OffsetNewest)
	_ = pc
}
`,
      'lonely/handler.go': `package lonely

import "github.com/Shopify/sarama"

type Lonely struct{}

func (l *Lonely) ConsumeClaim(s sarama.ConsumerGroupSession, claim sarama.ConsumerGroupClaim) error { return nil }
`,
      'kg/reader.go': `package kg

import "github.com/segmentio/kafka-go"

func readLoop(ctx context.Context) {
	r := kafka.NewReader(kafka.ReaderConfig{Brokers: []string{"k:9092"}, Topic: "clicks", GroupID: "g"})
	for {
		m, _ := r.ReadMessage(ctx)
		_ = m
	}
}
`,
    });
    // Extraction is per file: handler.go cannot see run.go's Consume, so it also keys its handler by type (known duplicate).
    expect(keysOf(idx, 'message')).toEqual(['mq:kafka:Lonely', 'mq:kafka:audit', 'mq:kafka:clicks', 'mq:kafka:orderHandler', 'mq:kafka:orders', 'mq:kafka:payments']);
    const orders = entry(idx, 'mq:kafka:orders');
    expect(orders).toMatchObject({ kind: 'message', protocol: 'kafka', pathTemplate: 'orders', framework: 'sarama', ruleId: 'go.kafka.consumer' });
    expect(orders.handler).toMatch(/consumer\/handler\.go#consumer\.orderHandler\.ConsumeClaim\(2\)$/);
    expect(entry(idx, 'mq:kafka:audit').handler).toBe(orders.handler);
    expect(entry(idx, 'mq:kafka:orderHandler').handler).toBe(orders.handler);
    expect(entry(idx, 'mq:kafka:payments').handler).toMatch(/consumer\/run\.go#consumer\.Run\(3\)$/);
    expect(entry(idx, 'mq:kafka:Lonely').handler).toMatch(/lonely\/handler\.go#lonely\.Lonely\.ConsumeClaim\(2\)$/);
    expect(entry(idx, 'mq:kafka:clicks')).toMatchObject({ framework: 'kafka-go', pathTemplate: 'clicks' });
    expect(entry(idx, 'mq:kafka:clicks').handler).toMatch(/kg\/reader\.go#kg\.readLoop\(1\)$/);
  });

  it('RabbitMQ, NATS, go-redis and NSQ consumers', async () => {
    const idx = await indexOf({
      'mq/rabbit.go': `package mq

import amqp "github.com/rabbitmq/amqp091-go"

func consumeTasks(ch *amqp.Channel) {
	q, _ := ch.QueueDeclare("tasks", true, false, false, false, nil)
	msgs, _ := ch.Consume(q.Name, "", false, false, false, false, nil)
	for d := range msgs { _ = d }
}

func consumeNamed(ch *amqp.Channel, name string) {
	msgs, _ := ch.Consume(name, "", true, false, false, false, nil)
	_ = msgs
}
`,
      'mq/nats.go': `package mq

import "github.com/nats-io/nats.go"

func onUpdate(m *nats.Msg) {}

func Listen(nc *nats.Conn) {
	nc.Subscribe("users.updated", onUpdate)
	nc.QueueSubscribe("orders.*", "workers", func(m *nats.Msg) { handle(m) })
}
`,
      'mq/redis.go': `package mq

import "github.com/redis/go-redis/v9"

func Watch(ctx context.Context, rdb *redis.Client) {
	sub := rdb.Subscribe(ctx, "events")
	_ = sub
	rdb.Get(ctx, "events")
}
`,
      'mq/nsq.go': `package mq

import "github.com/nsqio/go-nsq"

type mailHandler struct{}

func (h *mailHandler) HandleMessage(m *nsq.Message) error { return nil }

func StartMail() {
	c, _ := nsq.NewConsumer("mail", "ch", nsq.NewConfig())
	c.AddHandler(&mailHandler{})
}
`,
    });
    expect(keysOf(idx, 'message')).toEqual(['mq:nats:orders.*', 'mq:nats:users.updated', 'mq:nsq:mail', 'mq:rabbitmq:name', 'mq:rabbitmq:tasks', 'mq:redis:events']);
    const tasks = entry(idx, 'mq:rabbitmq:tasks');
    expect(tasks).toMatchObject({ kind: 'message', protocol: 'rabbitmq', pathTemplate: 'tasks', framework: 'amqp', ruleId: 'go.amqp.consumer' });
    expect(tasks.handler).toMatch(/mq\/rabbit\.go#mq\.consumeTasks\(1\)$/);
    expect(entry(idx, 'mq:nats:users.updated')).toMatchObject({ protocol: 'nats', framework: 'nats', ruleId: 'go.nats.subscribe', pathTemplate: 'users.updated' });
    expect(entry(idx, 'mq:nats:users.updated').handler).toMatch(/mq\/nats\.go#mq\.onUpdate\(1\)$/);
    expect(entry(idx, 'mq:nats:orders.*').handler).toMatch(/mq\/nats\.go#mq\.Listen\(1\)$/);
    expect(entry(idx, 'mq:redis:events')).toMatchObject({ protocol: 'redis', framework: 'go-redis' });
    expect(entry(idx, 'mq:redis:events').handler).toMatch(/mq\/redis\.go#mq\.Watch\(2\)$/);
    expect(entry(idx, 'mq:nsq:mail')).toMatchObject({ protocol: 'nsq', framework: 'nsq' });
    expect(entry(idx, 'mq:nsq:mail').handler).toMatch(/mq\/nsq\.go#mq\.mailHandler\.HandleMessage\(1\)$/);
  });

  it('robfig/cron jobs: AddFunc with a function, a method value and a closure; AddJob with a job type', async () => {
    const idx = await indexOf({
      'jobs/cron.go': `package jobs

import "github.com/robfig/cron/v3"

type ReportJob struct{}

func (ReportJob) Run() {}

func cleanup() {}

type svc struct{}

func (s *svc) Rotate() {}

func Start(s *svc) {
	c := cron.New()
	c.AddFunc("@every 1h", cleanup)
	c.AddFunc("0 3 * * *", s.Rotate)
	c.AddFunc("*/5 * * * *", func() { ping() })
	c.AddJob("0 0 * * 1", ReportJob{})
	c.Start()
}
`,
    });
    expect(keysOf(idx, 'schedule')).toEqual(['cron:ReportJob.Run', 'cron:Start.func1', 'cron:cleanup', 'cron:s.Rotate']);
    const clean = entry(idx, 'cron:cleanup');
    expect(clean).toMatchObject({ kind: 'schedule', protocol: 'cron', pathTemplate: '@every 1h', framework: 'robfig-cron', ruleId: 'go.cron' });
    expect(clean.handler).toMatch(/jobs\/cron\.go#jobs\.cleanup\(0\)$/);
    expect(entry(idx, 'cron:s.Rotate').handler).toMatch(/#jobs\.svc\.Rotate\(0\)$/);
    expect(entry(idx, 'cron:Start.func1')).toMatchObject({ pathTemplate: '*/5 * * * *' });
    expect(entry(idx, 'cron:Start.func1').handler).toMatch(/#jobs\.Start\(1\)$/);
    expect(entry(idx, 'cron:ReportJob.Run').handler).toMatch(/#jobs\.ReportJob\.Run\(0\)$/);
  });

  it('commands: cobra Use / RunE / Run, urfave/cli Command Name / Action; commands without a run function are skipped', async () => {
    const idx = await indexOf({
      'cmd/root.go': `package cmd

import "github.com/spf13/cobra"

var rootCmd = &cobra.Command{Use: "app", Short: "parent only"}

var importCmd = &cobra.Command{
	Use:  "import-users [file]",
	RunE: runImport,
}

func runImport(cmd *cobra.Command, args []string) error { return nil }

func newServeCmd() *cobra.Command {
	return &cobra.Command{Use: "serve", Run: func(cmd *cobra.Command, args []string) { serve() }}
}
`,
      'tool/main.go': `package main

import "github.com/urfave/cli/v2"

func migrate(c *cli.Context) error { return nil }

func main() {
	app := &cli.App{
		Name: "tool",
		Commands: []*cli.Command{
			{Name: "migrate", Action: migrate},
		},
	}
	_ = app
	cmd := &cli.Command{Name: "seed", Action: migrate}
	_ = cmd
}
`,
    });
    expect(keysOf(idx, 'cli')).toEqual(['cli:import-users', 'cli:seed', 'cli:serve']);
    const imp = entry(idx, 'cli:import-users');
    expect(imp).toMatchObject({ kind: 'cli', protocol: 'cli', pathTemplate: 'import-users', framework: 'cobra', ruleId: 'go.cobra.command' });
    expect(imp.handler).toMatch(/cmd\/root\.go#cmd\.runImport\(2\)$/);
    expect(entry(idx, 'cli:serve').handler).toMatch(/#cmd\.newServeCmd\(0\)$/);
    expect(entry(idx, 'cli:seed')).toMatchObject({ framework: 'urfave-cli', pathTemplate: 'seed' });
    expect(entry(idx, 'cli:seed').handler).toMatch(/tool\/main\.go#main\.migrate\(1\)$/);
  });

  it('Thrift: methods of the handler passed to New…Processor', async () => {
    const idx = await indexOf({
      'rpc/server.go': `package rpc

import (
	"github.com/apache/thrift/lib/go/thrift"
	"example.com/app/gen-go/user"
)

type UserHandler struct{}

func NewUserHandler() *UserHandler { return &UserHandler{} }

func (h *UserHandler) GetUser(ctx context.Context, id int64) (*user.User, error) { return nil, nil }
func (h *UserHandler) DeleteUser(ctx context.Context, id int64) error { return nil }
func (h *UserHandler) helper() {}

func Serve() {
	handler := NewUserHandler()
	processor := user.NewUserServiceProcessor(handler)
	mp := thrift.NewTMultiplexedProcessor()
	mp.RegisterProcessor("UserService", processor)
}
`,
    });
    expect(keysOf(idx, 'rpc')).toEqual(['rpc:thrift:UserService/DeleteUser', 'rpc:thrift:UserService/GetUser']);
    const get = entry(idx, 'rpc:thrift:UserService/GetUser');
    expect(get).toMatchObject({ kind: 'rpc', protocol: 'thrift', pathTemplate: 'UserService/GetUser', framework: 'thrift', ruleId: 'go.thrift.processor' });
    expect(get.handler).toMatch(/rpc\/server\.go#rpc\.UserHandler\.GetUser\(2\)$/);
  });

  it('negative: look-alike calls without the library imports produce no channel entries; HTTP routes unchanged', async () => {
    const idx = await indexOf({
      'app/main.go': `package main

import (
	"net/http"
	"github.com/gin-gonic/gin"
)

type Command struct{ Use string; Run func() }

func list(c *gin.Context) {
	conn, _ := proxy.Upgrade(c.Writer, c.Request, nil)
	_ = conn
}

func main() {
	r := gin.Default()
	r.GET("/items", list)
	bus.Subscribe("topic", list)
	q.Consume("queue", "", false, false, false, false, nil)
	sched.AddFunc("@daily", list)
	_ = &Command{Use: "x", Run: nil}
	_ = NewUserServiceProcessor(nil)
	http.ListenAndServe(":8080", r)
}
`,
    });
    expect(idx.entrypoints.map((e) => `${e.kind} ${e.entryKey}`)).toEqual(['http GET /items']);
  });
});
