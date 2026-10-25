// Rust frameworks — axum router chains across files (nest / merge / route_layer order, closures,
// extractor auth), actix-web (macros registered through scope / configure / service, resource builders, wrap), Rocket
// (macros, mount prefixes through route-list functions and re-exports, request guards declared by FromRequest impls),
// workspace crates (cross-crate handlers, server reachability) and the Rust sink rules.
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { describe, expect, it } from 'vitest';
import type { StructIndex } from '@xiezhi/contracts';
import { buildIndex, createSnapshot, Executor, loadRules, SnapshotView } from '@xiezhi/context';

async function indexOf(files: Record<string, string>): Promise<StructIndex> {
  const root = mkdtempSync(join(tmpdir(), 'ca-m1132-'));
  const src = join(root, 'repo');
  for (const [p, c] of Object.entries(files)) { mkdirSync(dirname(join(src, p)), { recursive: true }); writeFileSync(join(src, p), c); }
  const ex = new Executor({ scratchDir: join(root, 'exec') });
  const s = await createSnapshot({ source: { kind: 'local', path: src }, snapshotsDir: join(root, 'snapshots'), tmpDir: join(root, 'tmp'), executor: ex });
  const rules = loadRules();
  expect(rules.errors).toEqual([]);
  return (await buildIndex(new SnapshotView('repo', s.root, s.manifest), rules, { indexesDir: join(root, 'indexes') })).index;
}
const short = (id: string) => id.slice(id.indexOf('#') + 1);
const entries = (idx: StructIndex) => idx.entrypoints.map((e) => `${e.framework} ${e.httpMethod} ${e.pathTemplate} -> ${short(e.handler)} ${JSON.stringify(e.authSignals)}`).sort();
const sinks = (idx: StructIndex) => idx.sinks.filter((s) => s.category !== 'hardcoded_secret').map((s) => `${s.category} ${s.path}:${s.range.startLine} ${s.api}${s.taintHint ? ` (${s.taintHint})` : ''}`).sort();

const AXUM: Record<string, string> = {
  "Cargo.toml": "[package]\nname = \"axum-mini\"\nversion = \"0.1.0\"\n[dependencies]\naxum = \"0.7\"\nsqlx = { version = \"0.8\", features = [\"postgres\"] }\nreqwest = \"0.12\"\ntokio = { version = \"1\", features = [\"full\"] }\n",
  "src/api/admin.rs": "use axum::{routing::post, Router, Extension};\nuse crate::auth::Claims;\n\npub fn routes() -> Router {\n    Router::new().route(\"/reset\", post(reset))\n}\n\nasync fn reset(Extension(claims): Extension<Claims>) -> &'static str {\n    unsafe { std::ptr::null::<u8>(); }\n    \"ok\"\n}\n",
  "src/api/mod.rs": "pub mod users;\npub mod admin;\n\nuse axum::{middleware, routing::{get, post}, Router};\nuse crate::auth::require_auth;\n\npub fn router() -> Router {\n    Router::new()\n        .route(\"/login\", post(users::login))\n        .nest(\"/users\", users::routes())\n        .route_layer(middleware::from_fn(require_auth))\n        .nest(\"/admin\", admin::routes())\n}\n",
  "src/api/users.rs": "use axum::{extract::{Path, Query}, response::Redirect, routing::get, Json, Router};\nuse sqlx::PgPool;\nuse std::process::Command;\nuse crate::auth::Claims;\n\npub fn routes() -> Router {\n    Router::new()\n        .route(\"/:id\", get(show).delete(remove))\n        .route(\"/:id/avatar\", get(avatar))\n}\n\npub async fn login(Json(body): Json<LoginReq>) -> String {\n    let q = format!(\"SELECT id FROM users WHERE name = '{}'\", body.name);\n    let row = sqlx::query(&q).fetch_one(&pool()).await;\n    String::new()\n}\n\nasync fn show(Path(id): Path<i64>, claims: Claims) -> String {\n    let row = sqlx::query(\"SELECT * FROM users WHERE id = $1\").bind(id).fetch_one(&pool()).await;\n    String::new()\n}\n\nasync fn remove(Path(id): Path<String>) -> Redirect {\n    Command::new(\"sh\").arg(\"-c\").arg(format!(\"rm -rf /data/{}\", id)).output().unwrap();\n    Redirect::to(&id)\n}\n\nasync fn avatar(Query(q): Query<AvatarQ>) -> Vec<u8> {\n    let body = reqwest::get(&q.url).await.unwrap().bytes().await.unwrap();\n    std::fs::read(format!(\"/avatars/{}\", q.name)).unwrap()\n}\n",
  "src/auth.rs": "use axum::{extract::Request, middleware::Next, response::Response};\n\npub struct Claims { pub sub: String }\n\npub async fn require_auth(req: Request, next: Next) -> Response {\n    next.run(req).await\n}\n",
  "src/main.rs": "mod api;\nmod auth;\n\nuse axum::{routing::get, Router, middleware};\nuse crate::auth::require_auth;\n\n#[tokio::main]\nasync fn main() {\n    let public = Router::new().route(\"/health\", get(|| async { \"ok\" }));\n    let app = Router::new()\n        .merge(public)\n        .nest(\"/api\", api::router())\n        .layer(tower_http::trace::TraceLayer::new_for_http());\n    let listener = tokio::net::TcpListener::bind(\"0.0.0.0:3000\").await.unwrap();\n    axum::serve(listener, app).await.unwrap();\n}\n",
};
const ACTIX: Record<string, string> = {
  "Cargo.toml": "[package]\nname = \"actix-mini\"\n[dependencies]\nactix-web = \"4\"\nactix-web-httpauth = \"0.8\"\n",
  "src/main.rs": "mod routes;\nuse actix_web::{web, App, HttpServer};\nuse actix_web_httpauth::middleware::HttpAuthentication;\n\n#[actix_web::main]\nasync fn main() -> std::io::Result<()> {\n    HttpServer::new(|| {\n        App::new()\n            .service(routes::health)\n            .service(\n                web::scope(\"/api\")\n                    .wrap(HttpAuthentication::bearer(routes::validator))\n                    .configure(routes::users::config)\n                    .service(web::resource(\"/items/{id}\").route(web::get().to(routes::get_item)).route(web::delete().to(routes::delete_item)))\n            )\n            .route(\"/login\", web::post().to(routes::login))\n    })\n    .bind((\"127.0.0.1\", 8080))?\n    .run()\n    .await\n}\n",
  "src/routes/mod.rs": "pub mod users;\nuse actix_web::{get, web, HttpResponse, Responder};\n\n#[get(\"/health\")]\npub async fn health() -> impl Responder { HttpResponse::Ok() }\n\npub async fn validator(req: ServiceRequest, cred: BearerAuth) -> Result<ServiceRequest, Error> { Ok(req) }\n\npub async fn get_item(path: web::Path<String>) -> impl Responder {\n    let p = std::path::PathBuf::from(format!(\"/data/{}\", path));\n    actix_files::NamedFile::open(p)\n}\npub async fn delete_item(path: web::Path<i32>) -> impl Responder { HttpResponse::Ok() }\npub async fn login(form: web::Form<Login>) -> impl Responder { HttpResponse::Ok() }\n",
  "src/routes/users.rs": "use actix_web::{get, post, web, HttpResponse, Responder};\n\npub fn config(cfg: &mut web::ServiceConfig) {\n    cfg.service(web::scope(\"/users\").service(get_user).service(update_user));\n}\n\n#[get(\"/{id}\")]\nasync fn get_user(path: web::Path<i64>, user: web::ReqData<Claims>, pool: web::Data<Pool>) -> impl Responder {\n    let sql = format!(\"SELECT * FROM users WHERE id = {}\", path.into_inner());\n    client.query(sql.as_str(), &[]).await;\n    HttpResponse::Ok()\n}\n\n#[post(\"/{id}\", wrap = \"AdminGuard\")]\nasync fn update_user(body: web::Json<UpdateUser>) -> impl Responder { HttpResponse::Ok() }\n",
};
const ROCKET: Record<string, string> = {
  "Cargo.toml": "[package]\nname = \"rocket-mini\"\n[dependencies]\nrocket = \"0.5\"\n",
  "src/api.rs": "use rocket::response::Redirect;\nuse rocket::fs::NamedFile;\n\npub struct AdminUser;\n\n#[get(\"/users/<id>\")]\npub fn get_user(id: i64, admin: AdminUser) -> String { String::new() }\n\n#[post(\"/upload/<name>\", data = \"<data>\")]\npub async fn upload(name: &str, data: Vec<u8>) -> std::io::Result<()> {\n    std::fs::write(format!(\"/uploads/{}\", name), data)\n}\n\n#[get(\"/go?<to>\")]\npub fn go(to: String) -> Redirect { Redirect::to(to) }\n",
  "src/main.rs": "#[macro_use] extern crate rocket;\nmod api;\n\n#[get(\"/\")]\nfn index() -> &'static str { \"hi\" }\n\n#[launch]\nfn rocket() -> _ {\n    rocket::build()\n        .mount(\"/\", routes![index])\n        .mount(\"/api\", routes![api::get_user, api::upload, api::go])\n}\n",
};

describe('axum', () => {
  it('router chains: nest across files, route_layer applies to routes added before it, merged closure route, extractor auth', async () => {
    const idx = await indexOf(AXUM);
    expect(entries(idx)).toEqual([
      'axum DELETE /api/users/:id -> api::users.remove(1) [".route_layer(middleware::from_fn(require_auth))"]',
      'axum GET /api/users/:id -> api::users.show(2) [".route_layer(middleware::from_fn(require_auth))","extractor: Claims"]',
      'axum GET /api/users/:id/avatar -> api::users.avatar(1) [".route_layer(middleware::from_fn(require_auth))"]',
      'axum GET /health -> .<GET /health>(0) []',
      'axum POST /api/admin/reset -> api::admin.reset(1) ["extractor: Extension<Claims>"]',
      'axum POST /api/login -> api::users.login(1) [".route_layer(middleware::from_fn(require_auth))"]',
    ]);
    expect(sinks(idx)).toEqual([
      'cmdi src/api/users.rs:24 Command::new (string_concat)',
      'open_redirect src/api/users.rs:25 Redirect::to',
      'other src/api/admin.rs:9 unsafe 块',
      'path_traversal src/api/users.rs:30 std::fs::read (string_concat)',
      'sqli src/api/users.rs:14 sqlx::query (string_concat)',
      'ssrf src/api/users.rs:29 reqwest::get',
    ]);
    // The bound query with a constant SQL text is not a sink.
    expect(idx.sinks.some((s) => s.range.startLine === 18)).toBe(false);
  });
});

describe('actix-web', () => {
  it('macros under scope / configure, resource builders, App-level route, wrap middleware and wrap = "…", ReqData extractor', async () => {
    const idx = await indexOf(ACTIX);
    expect(entries(idx)).toEqual([
      'actix-web DELETE /api/items/{id} -> routes.delete_item(1) [".wrap(HttpAuthentication::bearer(routes::validator))"]',
      'actix-web GET /api/items/{id} -> routes.get_item(1) [".wrap(HttpAuthentication::bearer(routes::validator))"]',
      'actix-web GET /api/users/{id} -> routes::users.get_user(3) [".wrap(HttpAuthentication::bearer(routes::validator))","extractor: web::ReqData<Claims>"]',
      'actix-web GET /health -> routes.health(0) []',
      'actix-web POST /api/users/{id} -> routes::users.update_user(1) [".wrap(HttpAuthentication::bearer(routes::validator))","wrap = \\"AdminGuard\\""]',
      'actix-web POST /login -> routes.login(1) []',
    ]);
    expect(sinks(idx)).toEqual([
      'path_traversal src/routes/mod.rs:11 actix_files::NamedFile::open',
      'sqli src/routes/users.rs:10 client.query(…) (string_concat)',
    ]);
  });
});

describe('Rocket', () => {
  it('macros with mount prefixes, query segments dropped, request guards', async () => {
    const idx = await indexOf(ROCKET);
    expect(entries(idx)).toEqual([
      'rocket GET / -> .index(0) []',
      'rocket GET /api/go -> api.go(1) []',
      'rocket GET /api/users/<id> -> api.get_user(2) ["extractor: AdminUser"]',
      'rocket POST /api/upload/<name> -> api.upload(2) []',
    ]);
    expect(sinks(idx)).toEqual(['open_redirect src/api.rs:15 Redirect::to', 'path_traversal src/api.rs:11 std::fs::write (string_concat)']);
  });

  it('route-list functions, re-exports and computed bases; guards declared by FromRequest impls (also by delegation); Option guards are not enforcement', async () => {
    const idx = await indexOf({
      'Cargo.toml': '[package]\nname = "vw"\n[dependencies]\nrocket = "0.5"\n',
      'src/main.rs': `mod api;
mod auth;
fn launch(base: String) {
    rocket::build()
        .mount([base.as_str(), "/api"].concat(), api::core_routes())
        .mount("/", api::web_routes());
}
`,
      'src/api/mod.rs': 'mod core;\nmod web;\npub use crate::api::{core::routes as core_routes, web::routes as web_routes};\n',
      'src/api/core/mod.rs': `mod ciphers;
pub fn routes() -> Vec<Route> {
    let mut routes = Vec::new();
    routes.append(&mut ciphers::routes());
    routes
}
`,
      'src/api/core/ciphers.rs': `pub fn routes() -> Vec<Route> {
    routes![get_ciphers, delete_cipher, public_info]
}
#[get("/ciphers")]
async fn get_ciphers(headers: Headers) -> String { String::new() }
#[delete("/ciphers/<id>")]
async fn delete_cipher(id: &str, headers: OwnerHeaders) -> String { String::new() }
#[get("/info")]
async fn public_info(host: Host, maybe: Option<Headers>) -> String { String::new() }
`,
      'src/api/web.rs': 'pub fn routes() -> Vec<Route> { routes![index] }\n#[get("/")]\nfn index() -> &\'static str { "" }\n',
      'src/auth.rs': `pub struct Headers;
pub struct OwnerHeaders;
pub struct Host;
#[rocket::async_trait]
impl<'r> FromRequest<'r> for Headers {
    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        match req.headers().get_one("Authorization") { Some(_) => Outcome::Success(Headers), None => Outcome::Error((Status::Unauthorized, "no")) }
    }
}
#[rocket::async_trait]
impl<'r> FromRequest<'r> for OwnerHeaders {
    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let h = try_outcome!(Headers::from_request(req).await);
        Outcome::Success(OwnerHeaders)
    }
}
#[rocket::async_trait]
impl<'r> FromRequest<'r> for Host {
    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> { Outcome::Success(Host) }
}
`,
    });
    expect(entries(idx)).toEqual([
      'rocket DELETE /api/ciphers/<id> -> api::core::ciphers.delete_cipher(2) ["extractor: OwnerHeaders"]',
      'rocket GET / -> api::web.index(0) []',
      'rocket GET /api/ciphers -> api::core::ciphers.get_ciphers(1) ["extractor: Headers"]',
      'rocket GET /api/info -> api::core::ciphers.public_info(2) []',
    ]);
  });
});

describe('workspaces and test code', () => {
  it('handlers in sibling crates resolve; CLI crates and test code produce no sinks', async () => {
    const idx = await indexOf({
      'Cargo.toml': '[workspace]\nmembers = ["crates/*"]\n',
      'crates/server/Cargo.toml': '[package]\nname = "app-server"\n[dependencies]\naxum = "0.7"\napp-api = { path = "../api" }\n',
      'crates/server/src/main.rs': `use app_api::users::show;
fn main() { let app = Router::new().route("/users/:id", get(show)); }
`,
      'crates/api/Cargo.toml': '[package]\nname = "app-api"\n[dependencies]\nsqlx = "0.8"\n',
      'crates/api/src/lib.rs': 'pub mod users;\n',
      'crates/api/src/users.rs': `pub async fn show(Path(id): Path<String>) -> String {
    let q = format!("SELECT * FROM users WHERE id = '{}'", id);
    sqlx::query(&q);
    String::new()
}
#[cfg(test)]
mod tests {
    fn t() { let q = format!("DELETE FROM x WHERE id = {}", 1); sqlx::query(&q); }
}
`,
      'crates/cli/Cargo.toml': '[package]\nname = "app-cli"\n[dependencies]\nclap = "4"\n',
      'crates/cli/src/main.rs': 'fn main() { let p = std::env::args().nth(1).unwrap(); std::fs::read_to_string(&p).unwrap(); }\n',
    });
    expect(entries(idx)).toEqual(['axum GET /users/:id -> crates/api/users.show(1) []']);
    expect(sinks(idx)).toEqual(['sqli crates/api/src/users.rs:3 sqlx::query (string_concat)']);
  });
});
