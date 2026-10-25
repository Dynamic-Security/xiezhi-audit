// Python entries beyond HTTP — WebSocket routes and Channels consumers, Socket.IO events, Celery / Dramatiq /
// Kafka / RabbitMQ consumers, Celery beat / APScheduler / `schedule` jobs, click / typer / Django commands, Thrift handlers.
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { describe, expect, it } from 'vitest';
import type { StructIndex } from '@xiezhi/contracts';
import { buildIndex, createSnapshot, Executor, loadRules, SnapshotView } from '@xiezhi/context';

async function indexOf(files: Record<string, string>): Promise<StructIndex> {
  const root = mkdtempSync(join(tmpdir(), 'ca-m10py-'));
  const src = join(root, 'repo');
  for (const [p, c] of Object.entries(files)) { mkdirSync(dirname(join(src, p)), { recursive: true }); writeFileSync(join(src, p), c); }
  const ex = new Executor({ scratchDir: join(root, 'exec') });
  const s = await createSnapshot({ source: { kind: 'local', path: src }, snapshotsDir: join(root, 'snapshots'), tmpDir: join(root, 'tmp'), executor: ex });
  const v = new SnapshotView('repo', s.root, s.manifest);
  return (await buildIndex(v, loadRules(), { indexesDir: join(root, 'idx') })).index;
}

const short = (id: string | null | undefined) => (id ?? '').split('#').pop();
/** entryKey → [kind, protocol, pathTemplate, framework, handler] */
const table = (idx: StructIndex, prefix?: RegExp) => Object.fromEntries(idx.entrypoints.filter((e) => e.kind !== 'http' && (!prefix || prefix.test(e.entryKey)))
  .map((e) => [e.entryKey, [e.kind, e.protocol, e.pathTemplate, e.framework, short(e.handler)]]));

describe('Python sockets', () => {
  it('FastAPI websocket routes (router prefix) become socket entries; HTTP routes are unchanged', async () => {
    const idx = await indexOf({
      'app/main.py': `from fastapi import FastAPI, WebSocket, Depends
from app.chat import router
from app.auth import get_current_user

app = FastAPI()
app.include_router(router, prefix="/api")


@app.websocket("/ws")
async def ws(websocket: WebSocket, user=Depends(get_current_user)):
    await websocket.accept()


@app.get("/health")
def health():
    return {}
`,
      'app/__init__.py': '',
      'app/auth.py': 'def get_current_user():\n    return None\n',
      'app/chat.py': `from fastapi import APIRouter, WebSocket
router = APIRouter(prefix="/chat")


@router.websocket("/{room}")
async def room(websocket: WebSocket, room: str):
    await websocket.accept()
`,
    });
    expect(table(idx)).toEqual({
      'ws:/ws': ['socket', 'websocket', '/ws', 'fastapi', 'app.main.ws(2)'],
      'ws:/api/chat/{room}': ['socket', 'websocket', '/api/chat/{room}', 'fastapi', 'app.chat.room(2)'],
    });
    expect(idx.entrypoints.find((e) => e.entryKey === 'ws:/ws')!.authSignals).toContain('Depends(get_current_user)');
    expect(idx.entrypoints.find((e) => e.entryKey === 'GET /health')).toMatchObject({ kind: 'http', httpMethod: 'GET', handler: expect.stringContaining('app.main.health(0)') });
  });

  it('Django Channels consumers: routed by websocket_urlpatterns across files, unrouted by class name', async () => {
    const idx = await indexOf({
      'chat/__init__.py': '',
      'chat/consumers.py': `from channels.generic.websocket import AsyncWebsocketConsumer, JsonWebsocketConsumer


class ChatConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.accept()

    async def receive(self, text_data=None, bytes_data=None):
        pass


class EventsConsumer(JsonWebsocketConsumer):
    def receive_json(self, content):
        pass
`,
      'chat/routing.py': `from django.urls import path, re_path
from channels.routing import URLRouter
from channels.auth import AuthMiddlewareStack
from . import consumers
from .consumers import ChatConsumer

websocket_urlpatterns = [
    path("ws/chat/<room>/", ChatConsumer.as_asgi()),
]
`,
    });
    expect(table(idx)).toEqual({
      'ws:/ws/chat/<room>': ['socket', 'websocket', '/ws/chat/<room>', 'channels', 'chat.consumers.ChatConsumer.receive(2)'],
      'ws:EventsConsumer': ['socket', 'websocket', 'EventsConsumer', 'channels', 'chat.consumers.EventsConsumer.receive_json(1)'],
    });
  });

  it('Socket.IO events: Flask-SocketIO with namespace, python-socketio @sio.event / @sio.on, Namespace classes', async () => {
    const idx = await indexOf({
      'ws.py': `import socketio
from flask import Flask
from flask_socketio import SocketIO
from flask_login import login_required

app = Flask(__name__)
socketio_app = SocketIO(app)
sio = socketio.AsyncServer()


@socketio_app.on("message", namespace="/chat")
@login_required
def on_message(data):
    pass


@sio.event
async def connect(sid, environ):
    pass


@sio.on("typing")
async def typing(sid, data):
    pass


class AdminNs(socketio.AsyncNamespace):
    async def on_kick(self, sid, data):
        pass


sio.register_namespace(AdminNs("/admin"))
`,
    });
    expect(table(idx)).toEqual({
      'socketio:/chat#message': ['socket', 'socketio', '/chat#message', 'socketio', 'ws.on_message(1)'],
      'socketio:connect': ['socket', 'socketio', 'connect', 'socketio', 'ws.connect(2)'],
      'socketio:typing': ['socket', 'socketio', 'typing', 'socketio', 'ws.typing(2)'],
      'socketio:/admin#kick': ['socket', 'socketio', '/admin#kick', 'socketio', 'ws.AdminNs.on_kick(2)'],
    });
    expect(idx.entrypoints.find((e) => e.entryKey === 'socketio:/chat#message')!.authSignals).toEqual(['@login_required']);
  });
});

describe('Python message consumers', () => {
  it('Celery tasks (app.task across files, shared_task with name), Dramatiq actors', async () => {
    const idx = await indexOf({
      'proj/__init__.py': '',
      'proj/celery.py': `from celery import Celery
app = Celery("proj")
`,
      'proj/tasks.py': `from celery import shared_task
from proj.celery import app
import dramatiq


@app.task(bind=True)
def add(self, x, y):
    return x + y


@shared_task(name="emails.send")
def send_email(to):
    pass


@dramatiq.actor(queue_name="reports")
def build_report(rid):
    pass
`,
    });
    expect(table(idx)).toEqual({
      'mq:celery:add': ['message', 'celery', 'add', 'celery', 'proj.tasks.add(3)'],
      'mq:celery:emails.send': ['message', 'celery', 'emails.send', 'celery', 'proj.tasks.send_email(1)'],
      'mq:dramatiq:build_report': ['message', 'dramatiq', 'reports', 'dramatiq', 'proj.tasks.build_report(1)'],
    });
  });

  it('Kafka consumers (kafka-python ctor topics, confluent subscribe) and pika basic_consume', async () => {
    const idx = await indexOf({
      'kafka_worker.py': `from kafka import KafkaConsumer


def run():
    consumer = KafkaConsumer("orders", "refunds", group_id="g")
    for msg in consumer:
        handle(msg)


def handle(msg):
    pass
`,
      'confluent_worker.py': `from confluent_kafka import Consumer


def loop():
    c = Consumer({"group.id": "g"})
    c.subscribe(["payments"])
`,
      'rabbit.py': `import pika


def on_message(ch, method, properties, body):
    pass


def main():
    channel = pika.BlockingConnection().channel()
    channel.basic_consume(queue="tasks", on_message_callback=on_message)
`,
    });
    expect(table(idx)).toEqual({
      'mq:kafka:orders': ['message', 'kafka', 'orders', 'kafka-python', 'kafka_worker.run(0)'],
      'mq:kafka:refunds': ['message', 'kafka', 'refunds', 'kafka-python', 'kafka_worker.run(0)'],
      'mq:kafka:payments': ['message', 'kafka', 'payments', 'confluent-kafka', 'confluent_worker.loop(0)'],
      'mq:rabbitmq:tasks': ['message', 'rabbitmq', 'tasks', 'pika', 'rabbit.on_message(4)'],
    });
  });
});

describe('Python scheduled jobs', () => {
  it('Celery beat_schedule, APScheduler add_job / scheduled_job, schedule.every().do()', async () => {
    const idx = await indexOf({
      'proj/__init__.py': '',
      'proj/tasks.py': `from celery import shared_task


@shared_task
def cleanup():
    pass
`,
      'proj/celeryconfig.py': `from celery.schedules import crontab
beat_schedule = {
    "nightly-cleanup": {"task": "proj.tasks.cleanup", "schedule": crontab(hour=3, minute=0)},
}
`,
      'jobs.py': `import schedule
from apscheduler.schedulers.background import BackgroundScheduler

scheduler = BackgroundScheduler()


def sync_users():
    pass


def heartbeat():
    pass


@scheduler.scheduled_job("interval", minutes=5, id="poll")
def poll():
    pass


scheduler.add_job(sync_users, "cron", hour=1)
schedule.every(10).minutes.do(heartbeat)
`,
    });
    expect(table(idx, /^cron:/)).toEqual({
      'cron:proj.tasks.cleanup': ['schedule', 'cron', 'crontab(hour=3, minute=0)', 'celery', 'proj.tasks.cleanup(0)'],
      'cron:poll': ['schedule', 'cron', 'interval minutes=5', 'apscheduler', 'jobs.poll(0)'],
      'cron:sync_users': ['schedule', 'cron', 'cron hour=1', 'apscheduler', 'jobs.sync_users(0)'],
      'cron:heartbeat': ['schedule', 'cron', 'every(10).minutes', 'schedule', 'jobs.heartbeat(0)'],
    });
  });
});

describe('Python commands and Thrift', () => {
  it('click commands (group, named), typer commands, Django management commands', async () => {
    const idx = await indexOf({
      'cli.py': `import click


@click.group()
def cli():
    pass


@cli.command("import-users")
@click.option("--path")
def import_users(path):
    pass


@click.command()
def purge_cache():
    pass
`,
      'tool.py': `import typer
app = typer.Typer()


@app.command()
def export_data(out: str):
    pass
`,
      'shop/management/commands/rebuild_index.py': `from django.core.management.base import BaseCommand


class Command(BaseCommand):
    def handle(self, *args, **options):
        pass
`,
    });
    expect(table(idx)).toEqual({
      'cli:import-users': ['cli', 'cli', 'import-users', 'click', 'cli.import_users(1)'],
      'cli:purge-cache': ['cli', 'cli', 'purge-cache', 'click', 'cli.purge_cache(0)'],
      'cli:export-data': ['cli', 'cli', 'export-data', 'typer', 'tool.export_data(1)'],
      'cli:rebuild_index': ['cli', 'cli', 'rebuild_index', 'django', 'shop.management.commands.rebuild_index.Command.handle(0)'],
    });
  });

  it('Thrift Iface implementations: one rpc entry per public method', async () => {
    const idx = await indexOf({
      'server.py': `from gen.user import UserService


class UserHandler(UserService.Iface):
    def getUser(self, uid):
        pass

    def deleteUser(self, uid):
        pass

    def _helper(self):
        pass
`,
    });
    expect(table(idx)).toEqual({
      'rpc:thrift:UserService/getUser': ['rpc', 'thrift', 'UserService/getUser', 'thrift', 'server.UserHandler.getUser(1)'],
      'rpc:thrift:UserService/deleteUser': ['rpc', 'thrift', 'UserService/deleteUser', 'thrift', 'server.UserHandler.deleteUser(1)'],
    });
  });

  it('negative: look-alikes without the framework produce no entries', async () => {
    const idx = await indexOf({
      'other.py': `import redis
from fastapi import FastAPI

app = FastAPI()
bot = object()
r = redis.Redis()


@app.on_event("startup")
def startup():
    pass


@bot.command()
def ping():
    pass


@app.task
def not_celery():
    pass


def listen():
    p = r.pubsub()
    p.subscribe("news")


class Plain(object):
    def receive(self):
        pass
`,
    });
    expect(table(idx)).toEqual({});
  });
});
