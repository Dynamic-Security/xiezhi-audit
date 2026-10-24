// Ruby frameworks — Rails routes resolved to controller actions with the callbacks guarding them
// (inheritance, concerns, skip / only / except, Rails 8 allow_unauthenticated_access, http_basic_authenticate_with),
// Sinatra (classic, modular, namespaces, before filters, config.ru mounts), Grape (prefix, path version, resource,
// route_param, mounts), and the Ruby sink rules.
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { describe, expect, it } from 'vitest';
import type { StructIndex } from '@xiezhi/contracts';
import { buildIndex, createSnapshot, Executor, loadRules, SnapshotView } from '@xiezhi/context';

async function indexOf(files: Record<string, string>): Promise<StructIndex> {
  const root = mkdtempSync(join(tmpdir(), 'ca-m1131-'));
  const src = join(root, 'repo');
  for (const [p, c] of Object.entries(files)) { mkdirSync(dirname(join(src, p)), { recursive: true }); writeFileSync(join(src, p), c); }
  const ex = new Executor({ scratchDir: join(root, 'exec') });
  const s = await createSnapshot({ source: { kind: 'local', path: src }, snapshotsDir: join(root, 'snapshots'), tmpDir: join(root, 'tmp'), executor: ex });
  const rules = loadRules();
  expect(rules.errors).toEqual([]);
  return (await buildIndex(new SnapshotView('repo', s.root, s.manifest), rules, { indexesDir: join(root, 'indexes') })).index;
}
const short = (id: string) => id.slice(id.indexOf('#') + 1);
const entries = (idx: StructIndex) => idx.entrypoints.map((e) => `${e.httpMethod} ${e.pathTemplate} -> ${short(e.handler)}`).sort();
const entry = (idx: StructIndex, m: string, p: string) => idx.entrypoints.find((e) => e.httpMethod === m && e.pathTemplate === p)!;
const sinks = (idx: StructIndex) => idx.sinks.filter((s) => s.category !== 'hardcoded_secret').map((s) => `${s.category} ${s.path}:${s.range.startLine} ${s.api}`).sort();

const RAILS: Record<string, string> = {
  "Gemfile": "source 'https://rubygems.org'\ngem 'rails', '~> 7.1'\ngem 'devise'\ngem 'pundit'\n",
  "app/controllers/admin/base_controller.rb": "module Admin\n  class BaseController < ApplicationController\n    before_action :require_admin!\n  end\nend\n",
  "app/controllers/admin/dashboard_controller.rb": "module Admin\n  class DashboardController < BaseController\n    def show\n      render inline: params[:tpl]\n    end\n  end\nend\n",
  "app/controllers/admin/users_controller.rb": "class Admin::UsersController < Admin::BaseController\n  def index; end\n  def show\n    @user = User.find(params[:id])\n  end\n  def destroy\n    send_file params[:path]\n  end\nend\n",
  "app/controllers/application_controller.rb": "class ApplicationController < ActionController::Base\n  include Authentication\n  include Pundit::Authorization\n  before_action :set_locale\nend\n",
  "app/controllers/comments_controller.rb": "class CommentsController < ApplicationController\n  def create\n    system(\"notify #{params[:post_id]}\")\n    `echo #{params[:body]}`\n  end\n\n  def destroy\n    YAML.load(params[:data])\n    params[:klass].constantize.new\n    Net::HTTP.get(URI(params[:callback]))\n  end\nend\n",
  "app/controllers/concerns/authentication.rb": "module Authentication\n  extend ActiveSupport::Concern\n\n  included do\n    before_action :require_authentication\n  end\n\n  def require_authentication\n    redirect_to new_session_path unless current_user\n  end\nend\n",
  "app/controllers/home_controller.rb": "class HomeController < ApplicationController\n  allow_unauthenticated_access\n  def index; end\nend\n",
  "app/controllers/posts_controller.rb": "class PostsController < ApplicationController\n  before_action :load_post, only: %i[show edit update destroy publish]\n  after_action :verify_authorized\n\n  def index\n    @posts = Post.where(\"title LIKE '%#{params[:q]}%'\").order(params[:sort])\n  end\n\n  def show\n    authorize @post\n  end\n\n  def search\n    Post.find_by_sql(\"SELECT * FROM posts WHERE body = '#{params[:body]}'\")\n  end\n\n  def publish\n    authorize @post, :publish?\n    @post.update(post_params)\n  end\n\n  def update\n    @post.update(params.require(:post).permit!)\n  end\n\n  private\n\n  def load_post\n    @post = Post.find(params[:id])\n  end\n\n  def post_params\n    params.require(:post).permit(:title, :body, :user_id)\n  end\nend\n",
  "app/controllers/profiles_controller.rb": "class ProfilesController < ApplicationController\n  http_basic_authenticate_with name: \"dhh\", password: \"secret\", except: :show\n  def show; end\n  def update\n    current_user.update(params.require(:user).permit(:name, :role))\n  end\nend\n",
  "app/controllers/sessions_controller.rb": "class SessionsController < ApplicationController\n  skip_before_action :require_authentication, only: [:create]\n  skip_before_action :verify_authenticity_token\n  def create\n    user = User.find_by(email: params[:email])\n    redirect_to params[:return_to]\n  end\nend\n",
  "config/routes.rb": "Rails.application.routes.draw do\n  devise_for :users\n  root 'home#index'\n  get 'about', to: 'pages#about'\n  post '/login' => 'sessions#create'\n  resources :posts do\n    member do\n      post :publish\n    end\n    collection { get :search }\n    resources :comments, only: [:create, :destroy]\n  end\n  resource :profile, only: [:show, :update]\n  namespace :admin do\n    resources :users, except: [:new, :edit]\n    get 'dashboard', to: 'dashboard#show'\n  end\n  scope '/api', module: 'api' do\n    get 'status', to: 'status#show'\n  end\n  authenticate :user do\n    get 'reports', to: 'reports#index'\n  end\n  get 'old', to: redirect('/new')\nend\n",
};

const SINATRA_GRAPE: Record<string, string> = {
  "Gemfile": "gem 'sinatra'\ngem 'grape'\n",
  "app.rb": "require 'sinatra/base'\nrequire 'sinatra/namespace'\n\nclass AdminApp < Sinatra::Base\n  register Sinatra::Namespace\n  use Rack::Auth::Basic, \"Restricted\" do |u, p| u == 'a' end\n\n  before '/secret/*' do\n    authenticate!\n  end\n\n  get '/users/:id' do |id|\n    User.where(\"id = #{id}\").first\n  end\n\n  namespace '/secret' do\n    post '/keys' do\n      eval(params[:code])\n    end\n  end\n\n  get %r{/files/(\\w+)} do\n    send_file params[:captures].first\n  end\nend\n",
  "app/api/root.rb": "module API\n  class Root < Grape::API\n    prefix :api\n    format :json\n    mount API::V1::Users\n    mount API::V1::Public => '/public'\n  end\nend\n",
  "app/api/v1/public.rb": "module API\n  module V1\n    class Public < Grape::API\n      namespace :ping do\n        get do\n          { ok: true }\n        end\n      end\n    end\n  end\nend\n",
  "app/api/v1/users.rb": "module API\n  module V1\n    class Users < Grape::API\n      version 'v1', using: :path\n      before do\n        authenticate!\n      end\n      resource :users do\n        desc 'show'\n        route_param :id do\n          get do\n            User.find(params[:id])\n          end\n          delete do\n            Marshal.load(params[:blob])\n          end\n        end\n        post ':id/avatar' do\n          HTTParty.get(params[:url])\n        end\n      end\n    end\n  end\nend\n",
  "classic.rb": "require 'sinatra'\n\nhelpers do\n  def protected!\n    halt 401 unless authorized?\n  end\nend\n\nget '/' do\n  'hi'\nend\n\npost '/run' do\n  protected!\n  system(params[:cmd])\nend\n",
  "config.ru": "require './app'\nmap '/admin' do\n  run AdminApp\nend\nrun API::Root\n",
};

describe('Rails', () => {
  it('routes DSL: resources (only / except, nested, member / collection), singular resource, namespace, scope module, authenticate block, root', async () => {
    const idx = await indexOf(RAILS);
    expect(entries(idx)).toEqual([
      'DELETE /admin/users/:id -> Admin.UsersController.destroy(0)',
      'DELETE /posts/:id -> app/controllers/posts_controller.rb.PostsController',
      'DELETE /posts/:post_id/comments/:id -> app/controllers/comments_controller.rb.CommentsController.destroy(0)',
      'GET / -> app/controllers/home_controller.rb.HomeController.index(0)',
      'GET /about -> <unresolved:PagesController#about>',
      'GET /admin/dashboard -> Admin.DashboardController.show(0)',
      'GET /admin/users -> Admin.UsersController.index(0)',
      'GET /admin/users/:id -> Admin.UsersController.show(0)',
      'GET /api/status -> <unresolved:Api::StatusController#show>',
      'GET /posts -> app/controllers/posts_controller.rb.PostsController.index(0)',
      'GET /posts/:id -> app/controllers/posts_controller.rb.PostsController.show(0)',
      'GET /posts/:id/edit -> app/controllers/posts_controller.rb.PostsController',
      'GET /posts/new -> app/controllers/posts_controller.rb.PostsController',
      'GET /posts/search -> app/controllers/posts_controller.rb.PostsController.search(0)',
      'GET /profile -> app/controllers/profiles_controller.rb.ProfilesController.show(0)',
      'GET /reports -> <unresolved:ReportsController#index>',
      'PATCH /admin/users/:id -> Admin.UsersController',
      'PATCH /posts/:id -> app/controllers/posts_controller.rb.PostsController.update(0)',
      'PATCH /profile -> app/controllers/profiles_controller.rb.ProfilesController.update(0)',
      'POST /admin/users -> Admin.UsersController',
      'POST /login -> app/controllers/sessions_controller.rb.SessionsController.create(0)',
      'POST /posts -> app/controllers/posts_controller.rb.PostsController',
      'POST /posts/:id/publish -> app/controllers/posts_controller.rb.PostsController.publish(0)',
      'POST /posts/:post_id/comments -> app/controllers/comments_controller.rb.CommentsController.create(0)',
      'PUT /admin/users/:id -> Admin.UsersController',
      'PUT /posts/:id -> app/controllers/posts_controller.rb.PostsController.update(0)',
      'PUT /profile -> app/controllers/profiles_controller.rb.ProfilesController.update(0)',
    ]);
  });

  it('callbacks along the chain: concern before_action, namespace base controller, skips, allow_unauthenticated_access, in-action authorize', async () => {
    const idx = await indexOf(RAILS);
    expect(entry(idx, 'GET', '/').authSignals).toEqual([]);
    expect(entry(idx, 'POST', '/login').authSignals).toEqual([]);
    expect(entry(idx, 'GET', '/admin/users/:id').authSignals).toEqual(['before_action :require_authentication (Authentication)', 'before_action :require_admin! (Admin::BaseController)']);
    expect(entry(idx, 'POST', '/posts/:id/publish').authSignals).toContain('authorize @post, :publish? (in action)');
    expect(entry(idx, 'GET', '/profile').authSignals).toEqual(['before_action :require_authentication (Authentication)']);
    expect(entry(idx, 'PATCH', '/profile').authSignals).toContain('http_basic_authenticate_with name: "dhh", password: "secret", except: :show');
    expect(entry(idx, 'GET', '/reports').authSignals).toEqual(['routes: authenticate :user']);
    // set_locale is a callback but not an auth signal.
    expect(entry(idx, 'GET', '/posts').middlewares).toContain('set_locale');
    expect(entry(idx, 'GET', '/posts').authSignals.join()).not.toContain('set_locale');
  });

  it('sinks: AR string conditions (also chained), find_by_sql, commands, subshell, YAML, constantize, SSRF, send_file, render inline, redirect, CSRF skip, by-id, mass assignment', async () => {
    const idx = await indexOf(RAILS);
    expect(sinks(idx)).toEqual([
      'authz_object app/controllers/admin/users_controller.rb:4 按 ID 访问资源 User.find(…)',
      'authz_object app/controllers/posts_controller.rb:29 按 ID 访问资源 Post.find(…)',
      'business_logic app/controllers/posts_controller.rb:23 permit!',
      'business_logic app/controllers/posts_controller.rb:33 permit',
      'business_logic app/controllers/profiles_controller.rb:5 permit',
      'cmdi app/controllers/comments_controller.rb:3 Kernel#system',
      'cmdi app/controllers/comments_controller.rb:4 `…` (subshell)',
      'code_injection app/controllers/comments_controller.rb:9 constantize',
      'csrf app/controllers/sessions_controller.rb:3 skip_before_action',
      'deserialization app/controllers/comments_controller.rb:8 YAML.load',
      'open_redirect app/controllers/sessions_controller.rb:6 redirect_to',
      'path_traversal app/controllers/admin/users_controller.rb:7 send_file',
      'sqli app/controllers/posts_controller.rb:14 Post.find_by_sql(…)',
      'sqli app/controllers/posts_controller.rb:6 ActiveRecord order(…)',
      'sqli app/controllers/posts_controller.rb:6 ActiveRecord where(…)',
      'ssrf app/controllers/comments_controller.rb:10 Net::HTTP.get',
      'ssti app/controllers/admin/dashboard_controller.rb:4 render inline:',
    ]);
    // The lookup by email is not an id lookup; the scoped update is not a by-id sink.
    expect(idx.sinks.some((s) => s.api.includes('find_by('))).toBe(false);
  });
});

describe('Sinatra and Grape', () => {
  it('Sinatra: modular app mounted in config.ru, namespace, before filter with a pattern, Rack auth middleware, classic routes with helpers', async () => {
    const idx = await indexOf(SINATRA_GRAPE);
    const sin = idx.entrypoints.filter((e) => e.framework === 'sinatra');
    expect(sin.map((e) => `${e.httpMethod} ${e.pathTemplate}`).sort()).toEqual(['GET /', 'GET /admin/files/(\\w+)', 'GET /admin/users/:id', 'POST /admin/secret/keys', 'POST /run']);
    expect(entry(idx, 'POST', '/admin/secret/keys').authSignals).toContain("before '/secret/*': authenticate!");
    expect(entry(idx, 'GET', '/admin/users/:id').authSignals.join()).not.toContain('before');
    expect(entry(idx, 'GET', '/admin/users/:id').authSignals[0]).toMatch(/^use Rack::Auth::Basic/);
    expect(entry(idx, 'POST', '/run').authSignals).toEqual(['protected!']);
    expect(entry(idx, 'GET', '/').authSignals).toEqual([]);
    // Route blocks are symbols: calls inside them resolve.
    expect(idx.callEdges.some((e) => e.from.endsWith('<POST /run>(0)') && e.to?.endsWith('classic.rb.protected!(0)') && e.confidence === 'resolved')).toBe(true);
  });

  it('Sinatra: a template helper given a String compiles it on the server; a Symbol names a file', async () => {
    const idx = await indexOf({
      'Gemfile': "source 'https://rubygems.org'\ngem 'sinatra'\n",
      'app.rb': [
        'require "sinatra/base"',
        'class App < Sinatra::Base',
        '  get "/hello" do',
        '    erb "<h1>Hello #{params[\'name\']}</h1>"',
        '  end',
        '  get "/page" do',
        '    erb :page',
        '  end',
        '  get "/static" do',
        '    haml "%h1 Hi"',
        '  end',
        '  get "/raw" do',
        '    slim params[:tpl]',
        '  end',
        'end',
        '',
      ].join('\n'),
    });
    // Before: none of these was a sink (only ERB.new and Rails render inline: were).
    expect(sinks(idx).filter((x) => x.startsWith('ssti'))).toEqual(['ssti app.rb:13 sinatra slim(String)', 'ssti app.rb:4 sinatra erb(String)']);
  });

  it('Grape: root prefix, mounted APIs (with and without a path), path version, resource / route_param, before callbacks', async () => {
    const idx = await indexOf(SINATRA_GRAPE);
    const gr = idx.entrypoints.filter((e) => e.framework === 'grape');
    expect(gr.map((e) => `${e.httpMethod} ${e.pathTemplate}`).sort()).toEqual(['DELETE /api/v1/users/:id', 'GET /api/public/ping', 'GET /api/v1/users/:id', 'POST /api/v1/users/:id/avatar']);
    expect(entry(idx, 'GET', '/api/v1/users/:id').authSignals).toEqual(['before: authenticate!']);
    expect(entry(idx, 'GET', '/api/public/ping').authSignals).toEqual([]);
    expect(sinks(idx)).toEqual([
      'authz_object app/api/v1/users.rb:12 按 ID 访问资源 User.find(…)',
      'cmdi classic.rb:15 Kernel#system',
      'code_injection app.rb:18 eval(…)',
      'deserialization app/api/v1/users.rb:15 Marshal.load',
      'path_traversal app.rb:23 send_file',
      'sqli app.rb:13 ActiveRecord where(…)',
      'ssrf app/api/v1/users.rb:19 HTTParty.get',
    ]);
  });
});

describe('precision', () => {
  it('safe interpolations, heredoc SQL, helper output marked html_safe and internal dispatch are not sinks; request data is', async () => {
    const idx = await indexOf({
      Gemfile: "gem 'rails'\n",
      'app/models/message.rb': `class Message < ApplicationRecord
  def self.before(id)
    where("#{Message.table_name}.id < ?", id).order("#{table_name}.created_on DESC")
  end

  def self.stats(days)
    connection.select_all(<<~SQL.squish)
      SELECT count(*) FROM messages WHERE created_at > now() - interval '#{days} days'
    SQL
  end

  def self.totals
    connection.select_all(<<~SQL)
      SELECT count(*) FROM messages
    SQL
  end

  def format(name)
    content_tag(:b, name).html_safe + "<i>#{h(name)}</i>".html_safe
  end

  def unsafe(name)
    "<b>#{name}</b>".html_safe
  end

  def dispatch(kind)
    public_send("handle_#{kind}")
  end
end
`,
      'app/controllers/messages_controller.rb': `class MessagesController < ApplicationController
  def show
    @m = Message.public_send(params[:scope])
    Object.const_get(params[:klass])
  end
end
`,
    });
    expect(sinks(idx)).toEqual([
      'code_injection app/controllers/messages_controller.rb:3 Message.public_send(…)',
      'code_injection app/controllers/messages_controller.rb:4 Object.const_get',
      'sqli app/models/message.rb:7 connection.select_all(…)',
      'xss app/models/message.rb:23 html_safe',
    ]);
  });

  it('controller names: singular resources take the plural controller, acronym inflections match declared controllers', async () => {
    const idx = await indexOf({
      Gemfile: "gem 'rails'\n",
      'config/routes.rb': `Rails.application.routes.draw do
  resource :outbox, only: [:show], module: :activitypub
  resource :domain_blocks, only: [:show]
  resources :statuses, only: [] do
    resources :likes, only: [:index]
  end
end
`,
      'app/controllers/activity_pub/outboxes_controller.rb': 'class ActivityPub::OutboxesController < ApplicationController\n  def show; end\nend\n',
      'app/controllers/domain_blocks_controller.rb': 'class DomainBlocksController < ApplicationController\n  def show; end\nend\n',
      'app/controllers/likes_controller.rb': 'class LikesController < ApplicationController\n  def index; end\nend\n',
    });
    expect(entries(idx)).toEqual([
      'GET /domain_blocks -> app/controllers/domain_blocks_controller.rb.DomainBlocksController.show(0)',
      'GET /outbox -> ActivityPub.OutboxesController.show(0)',
      'GET /statuses/:status_id/likes -> app/controllers/likes_controller.rb.LikesController.index(0)',
    ]);
  });

  it('callbacks: lambda callbacks keep their text, bookkeeping callbacks are not auth, compact classes resolve their superclass lexically', async () => {
    const idx = await indexOf({
      Gemfile: "gem 'rails'\n",
      'config/routes.rb': "Rails.application.routes.draw do\n  namespace :admin do\n    resources :strikes, only: [:index]\n  end\n  resources :statuses, only: [:destroy]\nend\n",
      'app/controllers/application_controller.rb': 'class ApplicationController < ActionController::Base\n  before_action :update_user_sign_in\n  before_action :set_session_activity\nend\n',
      'app/controllers/strikes_controller.rb': 'class StrikesController < ApplicationController\n  before_action :authenticate_user!\n  def index; end\nend\n',
      'app/controllers/admin/strikes_controller.rb': 'class Admin::StrikesController < StrikesController\nend\n',
      'app/controllers/statuses_controller.rb': "class StatusesController < ApplicationController\n  before_action -> { doorkeeper_authorize! :write, :'write:statuses' }, only: [:destroy]\n  def destroy; end\nend\n",
    });
    expect(entry(idx, 'GET', '/admin/strikes').authSignals).toEqual(['before_action :authenticate_user! (StrikesController)']);
    const del = entry(idx, 'DELETE', '/statuses/:id');
    expect(del.authSignals).toEqual(["before_action -> { doorkeeper_authorize! :write, :'write:statuses' }, only: [:destroy]"]);
    expect(del.middlewares).toEqual(['update_user_sign_in', 'set_session_activity', "<-> { doorkeeper_authorize! :write, :'write:statuses' }>"]);
  });

  it('custom skip macros: class_methods in a concern that call skip_before_action', async () => {
    const idx = await indexOf({
      Gemfile: "gem 'rails'\n",
      'config/routes.rb': "Rails.application.routes.draw do\n  resources :books, only: [:index, :create]\nend\n",
      'app/controllers/concerns/authentication.rb': `module Authentication
  extend ActiveSupport::Concern
  included do
    before_action :require_member
  end
  class_methods do
    def allow_guests(**options)
      skip_before_action :require_member, **options
    end
  end
end
`,
      'app/controllers/application_controller.rb': 'class ApplicationController < ActionController::Base\n  include Authentication\nend\n',
      'app/controllers/books_controller.rb': 'class BooksController < ApplicationController\n  allow_guests only: [:index]\n  def index; end\n  def create; end\nend\n',
    });
    expect(entry(idx, 'GET', '/books').authSignals).toEqual([]);
    expect(entry(idx, 'POST', '/books').authSignals).toEqual(['before_action :require_member (Authentication)']);
  });
});

