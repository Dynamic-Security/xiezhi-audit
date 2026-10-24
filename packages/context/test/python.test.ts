// Python full audit — Flask / FastAPI / Django (+ DRF) entries with cross-file prefixes, calls,
// sinks with taint hints, auth signals; PyPI dependency reader; outbound HTTP client connection points.
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { describe, expect, it } from 'vitest';
import type { StructIndex } from '@xiezhi/contracts';
import { buildIndex, createSnapshot, declaredDependencies, Executor, extractConnections, loadRules, SnapshotView } from '@xiezhi/context';
import { pythonModuleOf, regexRoute } from '../src/index/extract-python.js';

async function viewOf(files: Record<string, string>): Promise<SnapshotView> {
  const root = mkdtempSync(join(tmpdir(), 'ca-m11py-'));
  const src = join(root, 'repo');
  for (const [p, c] of Object.entries(files)) { mkdirSync(dirname(join(src, p)), { recursive: true }); writeFileSync(join(src, p), c); }
  const ex = new Executor({ scratchDir: join(root, 'exec') });
  const s = await createSnapshot({ source: { kind: 'local', path: src }, snapshotsDir: join(root, 'snapshots'), tmpDir: join(root, 'tmp'), executor: ex });
  return new SnapshotView('repo', s.root, s.manifest);
}

async function indexOf(files: Record<string, string>): Promise<StructIndex> {
  const v = await viewOf(files);
  const root = mkdtempSync(join(tmpdir(), 'ca-m11py-idx-'));
  return (await buildIndex(v, loadRules(), { indexesDir: root })).index;
}

const keys = (idx: StructIndex) => idx.entrypoints.map((e) => e.entryKey).sort();
const entry = (idx: StructIndex, key: string) => idx.entrypoints.find((e) => e.entryKey === key);
const sinksOf = (idx: StructIndex, category: string) => idx.sinks.filter((s) => s.category === category);
const short = (id: string | null | undefined) => (id ?? '').split('#').pop();

describe('Flask', () => {
  it('routes with blueprint prefixes (same file and register_blueprint across files), methods and auth decorators', async () => {
    const idx = await indexOf({
      'app/__init__.py': `from flask import Flask
from app.invoices.views import bp as invoices_bp
from app import admin


def create_app():
    app = Flask(__name__)
    app.register_blueprint(invoices_bp, url_prefix="/api/invoices")
    app.register_blueprint(admin.bp)
    return app
`,
      'app/invoices/__init__.py': '',
      'app/invoices/views.py': `from flask import Blueprint, jsonify, request
from flask_login import login_required
from app.invoices.service import InvoiceService

bp = Blueprint("invoices", __name__, url_prefix="/ignored")
service = InvoiceService()


@bp.route("/<int:invoice_id>", methods=["GET", "DELETE"])
@login_required
def detail(invoice_id):
    return jsonify(service.load(invoice_id))


@bp.post("")
def create():
    return jsonify(service.create(request.json))
`,
      'app/invoices/service.py': `class InvoiceService:
    def load(self, invoice_id, include_lines=False):
        return self._find(invoice_id)

    def create(self, payload):
        return payload

    def _find(self, invoice_id):
        return invoice_id
`,
      'app/admin.py': `from flask import Blueprint
bp = Blueprint("admin", __name__, url_prefix="/admin")


@bp.before_request
def require_admin():
    pass


@bp.get("/stats")
def stats():
    return {}


class Cache:
    def get(self, key):
        return None


def warm(cache):
    cache.get("/not-a-route")
`,
    });
    expect(keys(idx)).toEqual(['DELETE /api/invoices/{}', 'GET /admin/stats', 'GET /api/invoices/{}', 'POST /api/invoices']);
    const d = entry(idx, 'GET /api/invoices/{}')!;
    expect(d.framework).toBe('flask');
    expect(short(d.handler)).toBe('app.invoices.views.detail(1)');
    expect(d.authSignals).toContain('@login_required');
    const stats = entry(idx, 'GET /admin/stats')!;
    expect(stats.middlewares).toContain('before_request:require_admin');
    expect(stats.authSignals).toContain('before_request:require_admin');
    expect(idx.authSignals.some((s) => s.kind === 'annotation' && s.detail === '@login_required' && short(s.target) === 'app.invoices.views.detail(1)')).toBe(true);
    // Call edges: module-level instance of an imported class, self calls with a default parameter.
    const edges = idx.callEdges.filter((e) => e.confidence === 'resolved').map((e) => `${short(e.from)} -> ${short(e.to)}`);
    expect(edges).toContain('app.invoices.views.detail(1) -> app.invoices.service.InvoiceService.load(2)');
    expect(edges).toContain('app.invoices.service.InvoiceService.load(2) -> app.invoices.service.InvoiceService._find(1)');
  });
});

describe('Flask views and module names', () => {
  it('add_url_rule with MethodView / wrapped functions, Flask-RESTful resources; module names from package roots', async () => {
    const idx = await indexOf({
      'backend/src/shop/__init__.py': '',
      'backend/src/shop/web/__init__.py': '',
      'backend/src/shop/web/routes.py': `from flask import Flask
from flask.views import MethodView
from flask_restful import Api, Resource
from flask_login import login_required
from . import handlers

app = Flask(__name__)
api = Api(app, prefix="/v2")


class OrderView(MethodView):
    decorators = [login_required]

    def get(self, order_id):
        return handlers.load(order_id)

    def put(self, order_id):
        return self.get(order_id)


class Stock(Resource):
    def get(self, sku):
        return {}


app.add_url_rule("/orders/<int:order_id>", view_func=OrderView.as_view("order"))
app.add_url_rule("/ping", "ping", login_required(handlers.ping), methods=["POST"])
api.add_resource(Stock, "/stock/<sku>")
`,
      'backend/src/shop/web/handlers.py': `def load(order_id):
    return len(str(order_id))


def ping():
    return "ok"
`,
    });
    expect(keys(idx)).toEqual(['GET /orders/{}', 'GET /v2/stock/{}', 'POST /ping', 'PUT /orders/{}']);
    expect(short(entry(idx, 'PUT /orders/{}')!.handler)).toBe('shop.web.routes.OrderView.put(1)');
    expect(entry(idx, 'GET /orders/{}')!.authSignals).toEqual(['decorators = [login_required]']);
    const ping = entry(idx, 'POST /ping')!;
    expect(short(ping.handler)).toBe('shop.web.handlers.ping(0)');
    expect(ping.authSignals).toContain('login_required');
    const edges = idx.callEdges.map((e) => `${short(e.from)} -> ${short(e.to)} ${e.confidence}`);
    expect(edges).toContain('shop.web.routes.OrderView.get(1) -> shop.web.handlers.load(1) resolved');
    expect(edges).toContain('shop.web.routes.OrderView.put(1) -> shop.web.routes.OrderView.get(1) resolved');
    // Builtins (len, str) are outside the repository graph: no edges.
    expect(edges.filter((e) => e.endsWith('unresolved'))).toEqual([]);
  });
});

describe('FastAPI', () => {
  it('APIRouter prefix + include_router prefix, Depends auth on parameters and router dependencies', async () => {
    const idx = await indexOf({
      'svc/main.py': `from fastapi import FastAPI, Depends
from svc.routers import items
from svc.deps import verify_token

app = FastAPI()
app.include_router(items.router, prefix="/api/v1", dependencies=[Depends(verify_token)])


@app.get("/health")
async def health():
    return {"ok": True}
`,
      'svc/__init__.py': '',
      'svc/routers/__init__.py': '',
      'svc/routers/items.py': `from typing import Annotated
from fastapi import APIRouter, Depends
from svc.deps import get_current_user

router = APIRouter(prefix="/items", tags=["items"])


@router.get("/{item_id}")
async def read_item(item_id: int, user=Depends(get_current_user)):
    return {"id": item_id}


@router.api_route("/bulk", methods=["PUT", "PATCH"])
def bulk(user: Annotated[dict, Depends(get_current_user)]):
    return []
`,
      'svc/deps.py': `def get_current_user():
    return None


def verify_token():
    return None
`,
    });
    expect(keys(idx)).toEqual(['GET /api/v1/items/{}', 'GET /health', 'PATCH /api/v1/items/bulk', 'PUT /api/v1/items/bulk']);
    const e = entry(idx, 'GET /api/v1/items/{}')!;
    expect(e.framework).toBe('fastapi');
    expect(e.authSignals).toEqual(expect.arrayContaining(['Depends(verify_token)', 'Depends(get_current_user)']));
    expect(entry(idx, 'GET /health')!.authSignals).toEqual([]);
    expect(idx.authSignals.some((s) => s.kind === 'annotation' && s.detail === 'Depends(get_current_user)' && short(s.target) === 'svc.routers.items.read_item(2)')).toBe(true);
  });
});

describe('Django', () => {
  it('include() prefixes across files, function views, class-based views, DRF router and permissions', async () => {
    const idx = await indexOf({
      'manage.py': 'import os\n',
      'clinic/__init__.py': '',
      'clinic/urls.py': `from django.urls import include, path, re_path

urlpatterns = [
    path("api/records/", include("records.urls")),
    re_path(r"^legacy/(?P<pk>\\d+)/$", include("records.urls")),
]
`,
      'clinic/settings.py': `MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
]
REST_FRAMEWORK = {"DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"]}
`,
      'records/__init__.py': '',
      'records/urls.py': `from django.urls import include, path
from rest_framework.routers import DefaultRouter
from . import views
from .views import RecordDetailView

router = DefaultRouter()
router.register(r"visits", views.VisitViewSet, basename="visit")

urlpatterns = [
    path("", views.record_list, name="record-list"),
    path("<int:record_id>/", RecordDetailView.as_view(), name="record-detail"),
    path("export/", views.ExportView.as_view()),
    path("api/", include(router.urls)),
]
`,
      'records/views.py': `from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.views import View
from django.views.decorators.http import require_GET
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated


@login_required
@require_GET
def record_list(request):
    return None


class RecordDetailView(LoginRequiredMixin, View):
    def get(self, request, record_id):
        return None

    def post(self, request, record_id):
        return None


class ExportView(View):
    def get(self, request):
        return None


class VisitViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]

    def retrieve(self, request, pk=None):
        return None

    @action(detail=True, methods=["post"], url_path="close")
    def close(self, request, pk=None):
        return None
`,
    });
    const k = keys(idx);
    expect(k).toEqual(expect.arrayContaining([
      'GET /api/records', 'GET /api/records/{}', 'POST /api/records/{}', 'GET /api/records/export', 'GET /legacy/{}/export',
      'GET /api/records/api/visits', 'POST /api/records/api/visits', 'GET /api/records/api/visits/{}', 'DELETE /api/records/api/visits/{}',
      'POST /api/records/api/visits/{}/close',
    ]));
    const list = entry(idx, 'GET /api/records')!;
    expect(list.framework).toBe('django');
    expect(short(list.handler)).toBe('records.views.record_list(1)');
    expect(list.authSignals).toContain('@login_required');
    const detail = entry(idx, 'POST /api/records/{}')!;
    expect(short(detail.handler)).toBe('records.views.RecordDetailView.post(2)');
    expect(detail.authSignals).toContain('LoginRequiredMixin');
    expect(entry(idx, 'GET /api/records/export')!.authSignals).toEqual([]);
    const retrieve = entry(idx, 'GET /api/records/api/visits/{}')!;
    expect(short(retrieve.handler)).toBe('records.views.VisitViewSet.retrieve(2)');
    expect(retrieve.authSignals).toContain('permission_classes = [IsAuthenticated]');
    // Inherited ModelViewSet actions point at the class.
    expect(short(entry(idx, 'DELETE /api/records/api/visits/{}')!.handler)).toBe('records.views.VisitViewSet');
    expect(idx.authSignals.filter((s) => s.kind === 'security_config').map((s) => s.detail)).toEqual(expect.arrayContaining([
      'MIDDLEWARE: django.contrib.auth.middleware.AuthenticationMiddleware',
      'REST_FRAMEWORK: DEFAULT_PERMISSION_CLASSES: ["rest_framework.permissions.IsAuthenticated"]',
    ]));
  });

  it('non-route calls named path / get are not entries', async () => {
    const idx = await indexOf({
      'tools/util.py': `import os
from pathlib import Path


def path(a, b):
    return os.path.join(a, b)


def run(app):
    path("x/", "y")
    app.get("/nope")
    Path("a").exists()
`,
    });
    expect(idx.entrypoints).toEqual([]);
  });
});

describe('sinks', () => {
  it('SQL with f-string / % / + / format is string_concat; parameterized and constant SQL is constant', async () => {
    const idx = await indexOf({
      'repo/records.py': `from django.db import connection
from sqlalchemy import text


class RecordRepository:
    def search(self, patient_id, sort):
        sql = f"SELECT * FROM records WHERE patient_id = %s ORDER BY {sort}"
        with connection.cursor() as cursor:
            cursor.execute(sql, [patient_id])
            return cursor.fetchall()

    def count(self, patient_id):
        with connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM records WHERE patient_id = %s", [patient_id])

    def by_status(self, session, status):
        q = "SELECT * FROM records WHERE status = '%s'" % status
        session.execute(text(q))

    def by_name(self, cur, name):
        cur.execute("SELECT * FROM p WHERE name = '" + name + "'")
        cur.execute("SELECT * FROM p WHERE name = '{}'".format(name))
`,
    });
    const sq = sinksOf(idx, 'sqli').map((s) => `${short(s.symbolId)} L${s.range.startLine} ${s.taintHint ?? '-'}`);
    expect(sq).toEqual(expect.arrayContaining([
      'repo.records.RecordRepository.search(2) L9 string_concat',
      'repo.records.RecordRepository.count(1) L14 constant',
      'repo.records.RecordRepository.by_status(2) L18 string_concat',
      'repo.records.RecordRepository.by_name(2) L21 string_concat',
      'repo.records.RecordRepository.by_name(2) L22 string_concat',
    ]));
    expect(sinksOf(idx, 'sqli').some((s) => s.api === 'sqlalchemy.text')).toBe(true);
  });

  it('sqlite3 / DB-API execute on a receiver with an uninformative name is a sink when the file imports the driver', async () => {
    const idx = await indexOf({
      'app/db.py': `import sqlite3

def conn():
    return sqlite3.connect("notes.db")

def find_notes(owner, keyword):
    c = conn()
    sql = "SELECT * FROM notes WHERE owner = '%s' AND title LIKE '%%%s%%'" % (owner, keyword)
    return c.execute(sql).fetchall()

def get_note(note_id):
    c = conn()
    return c.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()

def via_conn(name):
    conn().execute("SELECT * FROM notes WHERE title = '" + name + "'")
`,
      'app/jobs.py': `def run(r, q):
    r.execute(q)
`,
    });
    const sq = sinksOf(idx, 'sqli').map((s) => `${short(s.symbolId)} L${s.range.startLine} ${s.taintHint ?? '-'}`);
    expect(sq).toEqual(expect.arrayContaining([
      'app.db.find_notes(2) L9 string_concat',
      'app.db.get_note(1) L13 constant',
      'app.db.via_conn(1) L16 string_concat',
    ]));
    // One sink per call: the conn() receiver stays with python.db.cursor-execute.
    expect(sq.filter((x) => x.includes('L16'))).toHaveLength(1);
    // No driver import, no name hint: not a sink.
    expect(sinksOf(idx, 'sqli').some((s) => s.symbolId.includes('jobs'))).toBe(false);
  });

  it('cmdi / code injection / deserialization / ssrf / path traversal / ssti / redirect / xxe, and safe variants', async () => {
    const idx = await indexOf({
      'svc/tasks.py': `import os
import pickle
import subprocess
import yaml
import requests
from subprocess import check_output
from urllib.request import urlopen
from flask import redirect, render_template_string, send_file, url_for
from lxml import etree


def run(cmd, name, blob, url, path, tpl, nxt, xml):
    os.system("convert " + name)
    subprocess.run(f"tar czf {name}.tgz", shell=True)
    subprocess.run(["pg_isready"], check=False)
    check_output(["ls", name])
    eval(cmd)
    eval("1 + 1")
    pickle.loads(blob)
    yaml.load(blob)
    yaml.load(blob, Loader=yaml.SafeLoader)
    yaml.safe_load(blob)
    requests.get(url, timeout=5)
    urlopen(url)
    open(path)
    send_file(path)
    render_template_string(tpl)
    redirect(nxt)
    redirect(url_for("index"))
    redirect("/home")
    etree.fromstring(xml)
`,
    });
    const cats = (c: string) => sinksOf(idx, c).map((s) => `L${s.range.startLine} ${s.api}${s.taintHint ? ` ${s.taintHint}` : ''}`).sort();
    expect(cats('cmdi')).toEqual([
      'L13 os.system string_concat', 'L14 subprocess.run shell=True string_concat', 'L15 subprocess.run constant', 'L16 subprocess.check_output',
    ].sort());
    expect(cats('code_injection')).toEqual(['L17 eval']);
    expect(cats('deserialization')).toEqual(['L19 pickle.loads', 'L20 yaml.load']);
    expect(cats('ssrf')).toEqual(['L23 requests.get', 'L24 urllib.request.urlopen']);
    expect(cats('path_traversal')).toEqual(['L25 builtins.open', 'L26 flask.send_file']);
    expect(cats('ssti')).toEqual(['L27 flask.render_template_string']);
    expect(cats('open_redirect')).toEqual(['L28 flask.redirect']);
    expect(cats('xxe')).toEqual(['L31 lxml.etree.fromstring']);
  });

  it('business-sensitive sinks: by-id lookups and state / amount writes; dict.get is not one', async () => {
    const idx = await indexOf({
      'billing/service.py': `from django.shortcuts import get_object_or_404
from billing.models import Invoice


class InvoiceService:
    def load(self, request, invoice_id):
        page = request.GET.get("page")
        options = {"a": 1}.get("a")
        inv = Invoice.objects.get(pk=invoice_id)
        other = get_object_or_404(Invoice, id=invoice_id)
        mine = Invoice.objects.filter(owner=request.user, id=invoice_id).first()
        return inv, other, mine, page, options

    def pay(self, inv, amount):
        inv.status = "paid"
        inv.balance -= amount
        Invoice.objects.filter(pk=inv.pk).update(status="paid")
        inv.save()
`,
    });
    const az = sinksOf(idx, 'authz_object').map((s) => `L${s.range.startLine}`);
    expect(az).toEqual(['L10', 'L11', 'L17', 'L9']);
    const bl = sinksOf(idx, 'business_logic').map((s) => `L${s.range.startLine}`);
    expect(bl).toEqual(['L15', 'L16', 'L17']);
  });
});

describe('robustness', () => {
  it('broken files and unbalanced brackets do not throw; module names and re_path conversion', async () => {
    const idx = await indexOf({
      'pkg/__init__.py': '',
      'pkg/broken.py': 'def f(:\n    x = (\n' + 'path("a/", view)\n'.repeat(2000) + 'class \n',
      'pkg/ok.py': 'def g(a, *, b=1, **kw):\n    return g(1, b=2)\n',
    });
    expect(idx.symbols.some((s) => s.symbolId.endsWith('#pkg.ok.g(2)'))).toBe(true);
    expect(idx.callEdges.find((e) => e.from.endsWith('#pkg.ok.g(2)'))?.confidence).toBe('resolved');
    expect(pythonModuleOf('src/app/main.py')).toBe('app.main');
    expect(pythonModuleOf('backend/api/__init__.py', new Set(['backend/api']))).toBe('api');
    expect(regexRoute('^invoices/(?P<pk>[0-9]+)/lines/(\\d+)/$')).toBe('invoices/{pk}/lines/{}/');
  });
});

describe('dependencies and connections', () => {
  it('reads requirements, pyproject (PEP 621 + Poetry), Pipfile and lock files; locks supersede manifests', async () => {
    const v = await viewOf({
      'requirements.txt': 'Django==4.2.1\nrequests>=2.28  # http\n-r base.txt\nPyYAML[libyaml]==5.3.1 ; python_version >= "3.8"\ngit+https://example.com/x.git#egg=x\n',
      'svc/pyproject.toml': `[project]
name = "svc"
dependencies = [
  "fastapi==0.110.0",
  "Jinja2>=3",
]

[tool.poetry.dependencies]
python = "^3.11"
urllib3 = "1.26.5"
lxml = { version = "4.9.1", extras = ["html"] }
`,
      'svc/poetry.lock': `[[package]]
name = "jinja2"
version = "3.1.2"

[[package]]
name = "fastapi"
version = "0.110.0"
`,
      'web/Pipfile': '[packages]\nflask = "==2.0.1"\npillow = "*"\n',
      'web/Pipfile.lock': JSON.stringify({ default: { flask: { version: '==2.0.1' }, werkzeug: { version: '==2.0.2' } } }),
      'tool/uv.lock': 'version = 1\n\n[[package]]\nname = "pyyaml"\nversion = "6.0.1"\n',
    });
    const deps = declaredDependencies(v).filter((d) => d.ecosystem === 'pypi').map((d) => `${d.path} ${d.name}@${d.version ?? '?'}`).sort();
    expect(deps).toEqual([
      'requirements.txt django@4.2.1',
      'requirements.txt pyyaml@5.3.1',
      'requirements.txt requests@?',
      'svc/poetry.lock fastapi@0.110.0',
      'svc/poetry.lock jinja2@3.1.2',
      'svc/pyproject.toml lxml@4.9.1',
      'svc/pyproject.toml urllib3@1.26.5',
      'tool/uv.lock pyyaml@6.0.1',
      'web/Pipfile pillow@?',
      'web/Pipfile.lock flask@2.0.1',
      'web/Pipfile.lock werkzeug@2.0.2',
    ]);
  });

  it('requests / httpx / aiohttp calls become outbound HTTP connection points', async () => {
    const v = await viewOf({
      'svc/client.py': `import httpx
import requests

BILLING = "http://billing-svc:8080"


def fetch(invoice_id):
    requests.get(f"{BILLING}/api/invoices/{invoice_id}")
    requests.request("POST", "http://audit-svc/api/events")
    requests.post(BILLING + "/api/payments", json={})


async def sync():
    async with httpx.AsyncClient(base_url="http://stock-svc") as client:
        await client.get("/api/stock")
`,
    });
    const cs = (await extractConnections(v, null, null)).filter((c) => c.kind === 'http' && c.side === 'consumes');
    expect(cs.map((c) => `${c.key.method ?? '-'} ${c.key.pathTemplate} @${c.serviceHint ?? '-'} ${c.extraction}`).sort()).toEqual([
      'GET /api/invoices/{?} @billing-svc partial',
      'GET /api/stock @stock-svc literal',
      'POST /api/events @audit-svc literal',
      'POST /api/payments @billing-svc constant_folded',
    ]);
  });
});
