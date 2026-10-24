// GORM sinks — an inline condition taken from the request (`db.Find(&album, mux.Vars(r)["id"])`) and
// clauses built by concatenation / fmt.Sprintf; parameterized and numeric conditions are not sinks.
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { buildIndex, createSnapshot, Executor, loadRules, SnapshotView } from '@xiezhi/context';

async function indexOf(files: Record<string, string>) {
  const root = mkdtempSync(join(tmpdir(), 'ca-m12gorm-'));
  const src = join(root, 'repo');
  for (const [p, c] of Object.entries(files)) { mkdirSync(dirname(join(src, p)), { recursive: true }); writeFileSync(join(src, p), c); }
  const ex = new Executor({ scratchDir: join(root, 'exec') });
  const s = await createSnapshot({ source: { kind: 'local', path: src }, snapshotsDir: join(root, 'snapshots'), tmpDir: join(root, 'tmp'), executor: ex });
  return (await buildIndex(new SnapshotView('repo', s.root, s.manifest), loadRules(), { indexesDir: join(root, 'idx') })).index;
}

describe('GORM sinks', () => {
  it('request strings as inline conditions and concatenated clauses; not parameters, literals or numbers', async () => {
    const idx = await indexOf({
      'go.mod': 'module example.com/photo\n\ngo 1.22\n',
      'routes/downloads.go': `package routes

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	"gorm.io/gorm"
)

func Register(db *gorm.DB, router *mux.Router) {
	router.HandleFunc("/album/{album_id}", func(w http.ResponseWriter, r *http.Request) {
		albumID := mux.Vars(r)["album_id"]
		var album Album
		db.Find(&album, albumID)
		db.First(&album, mux.Vars(r)["id"])
		n, _ := strconv.Atoi(mux.Vars(r)["n"])
		db.First(&album, n)
		db.First(&album, "id = ?", albumID)
		db.First(&album, 10)
		order := r.URL.Query().Get("order")
		db.Where("title = '" + order + "'").Find(&album)
		db.Order(fmt.Sprintf("%s desc", order)).Find(&album)
		db.Where("title = ?", order).Find(&album)
		db.Where("title = 'x' AND " + "owner_id = 1").Find(&album)
	})
}

func byID(db *gorm.DB, id int) (a Album) { db.First(&a, id); return }
`,
    });
    const gorm = idx.sinks.filter((s) => s.ruleId.startsWith('go.gorm')).map((s) => `${s.ruleId}@${s.range.startLine}:${s.taintHint}`).sort();
    expect(gorm).toEqual([
      'go.gorm.raw-clause@23:string_concat', // concatenated request value
      'go.gorm.raw-clause@24:string_concat', // fmt.Sprintf
      'go.gorm.raw-clause@26:string_concat', // two literals concatenated also match; the hunt rules it out
      'go.gorm.request-condition@16:request_string',
      'go.gorm.request-condition@17:request_string',
    ]);
    expect(idx.sinks.find((s) => s.ruleId === 'go.gorm.request-condition')).toMatchObject({ category: 'sqli', api: 'gorm Find(dest, 请求字符串作为内联条件)' });
  });

  it('only with a GORM import', async () => {
    const idx = await indexOf({
      'go.mod': 'module example.com/x\n\ngo 1.22\n',
      'x.go': 'package x\n\nimport "github.com/gorilla/mux"\n\nfunc f(db Store, r *Req) { db.Find(&a, mux.Vars(r)["id"]) }\n',
    });
    expect(idx.sinks.filter((s) => s.ruleId.startsWith('go.gorm'))).toEqual([]);
  });
});
