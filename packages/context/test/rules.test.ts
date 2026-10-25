// entry rules (flamego / macaron, chi, JAX-RS) and business-sensitive sink rules, on small inline sources.
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { Executor, SnapshotView, buildIndex, createSnapshot, loadRules } from '@xiezhi/context';

async function indexOf(files: Record<string, string>) {
  const root = mkdtempSync(join(tmpdir(), 'ca-m9rules-'));
  const src = join(root, 'repo');
  for (const [p, c] of Object.entries(files)) { mkdirSync(dirname(join(src, p)), { recursive: true }); writeFileSync(join(src, p), c); }
  const ex = new Executor({ scratchDir: join(root, 'exec') });
  const s = await createSnapshot({ source: { kind: 'local', path: src }, snapshotsDir: join(root, 'snapshots'), tmpDir: join(root, 'tmp'), executor: ex });
  const v = new SnapshotView('repo', s.root, s.manifest);
  return (await buildIndex(v, loadRules(), { indexesDir: join(root, 'indexes') })).index;
}

describe('entry rules', () => {
  it('JAX-RS resource methods with class and method @Path', async () => {
    const idx = await indexOf({
      'src/main/java/t/DeviceResource.java': `package t;
import javax.ws.rs.*;
@Path("devices")
public class DeviceResource {
    @GET
    @Path("{id}")
    public String get(@PathParam("id") long id) { return "" + id; }
    @POST
    @Path("{id}/image")
    public String upload(@PathParam("id") long id) { return ""; }
    @DELETE
    public void remove() { }
}
`,
    });
    const keys = idx.entrypoints.map((e) => `${e.entryKey.split(':').pop()}`).sort();
    expect(keys).toEqual(['DELETE /devices', 'GET /devices/{}', 'POST /devices/{}/image']);
  });

  it('flamego / chi routes with title-case verbs; non-route Get calls are ignored', async () => {
    const idx = await indexOf({
      'internal/web/web.go': `package web
import "github.com/flamego/flamego"
func Run(f *flamego.Flame, cache Cache) {
	f.Get("/attachments/{uuid}", serveAttachment)
	f.Post("/api/web/{owner}/{repo}/watch", reqSignIn, postWatch)
	var v string
	cache.Get("key", &v)
}
`,
      'server/router.go': `package server
import "github.com/go-chi/chi/v5"
func routes(r chi.Router) {
	r.Get("/api/artist", getArtists)
	r.Post("/api/share", createShare)
}
`,
    });
    const keys = idx.entrypoints.map((e) => e.entryKey.split(':').pop()).sort();
    expect(keys).toEqual(['GET /api/artist', 'GET /attachments/{}', 'POST /api/share', 'POST /api/web/{}/{}/watch']);
  });
});

describe('business-sensitive rules', () => {
  it('state writes, amount writes and by-id access are indexed as business sinks', async () => {
    const idx = await indexOf({
      'src/main/java/t/OrderService.java': `package t;
public class OrderService {
    private OrderRepo repo;
    public void pay(Long id, java.math.BigDecimal amt) {
        Order o = repo.findById(id);
        o.setStatus("PAID");
        o.setAmount(amt);
    }
}
`,
      'internal/store/order.go': `package store
import "gorm.io/gorm"
func Load(db *gorm.DB, id int64) (Order, error) {
	var o Order
	err := db.First(&o, id).Error
	db.Model(&o).Update("status", "paid")
	return o, err
}
`,
    });
    const business = idx.sinks.filter((s) => (s.ruleId ?? '').includes('.business.')).map((s) => `${s.ruleId}:${s.category}`).sort();
    expect(business).toEqual([
      'go.business.by-id:authz_object', 'go.business.state-write:business_logic',
      'java.business.amount-write:business_logic', 'java.business.find-by-id:authz_object', 'java.business.state-write:business_logic',
    ]);
  });
});
