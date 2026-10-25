// GraphQL resolvers as `rpc` entries (`rpc:graphql:<Type>/<field>`) in Go (gqlgen), Java (Spring for GraphQL,
// DGS, graphql-java-kickstart) and JS / TS (resolver maps, NestJS / TypeGraphQL decorators), named after the schema.
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { describe, expect, it } from 'vitest';
import type { StructIndex } from '@xiezhi/contracts';
import { buildIndex, createSnapshot, Executor, graphqlStateOrById, loadRules, scanGraphql, SnapshotView } from '@xiezhi/context';

async function viewOf(files: Record<string, string>): Promise<SnapshotView> {
  const root = mkdtempSync(join(tmpdir(), 'ca-m12gql-'));
  const src = join(root, 'repo');
  for (const [p, c] of Object.entries(files)) { mkdirSync(dirname(join(src, p)), { recursive: true }); writeFileSync(join(src, p), c); }
  const ex = new Executor({ scratchDir: join(root, 'exec') });
  const s = await createSnapshot({ source: { kind: 'local', path: src }, snapshotsDir: join(root, 'snapshots'), tmpDir: join(root, 'tmp'), executor: ex });
  return new SnapshotView('repo', s.root, s.manifest);
}
const indexOf = async (files: Record<string, string>) => (await buildIndex(await viewOf(files), loadRules(), { indexesDir: mkdtempSync(join(tmpdir(), 'ca-m12gql-i-')) })).index;
const gql = (idx: StructIndex) => idx.entrypoints.filter((e) => e.entryKey.startsWith('rpc:graphql:')).map((e) => e.entryKey).sort();
const entry = (idx: StructIndex, key: string) => idx.entrypoints.find((e) => e.entryKey === key)!;

const SCHEMA = `# Photo sharing
directive @isAuthorized on FIELD_DEFINITION
directive @isAdmin on FIELD_DEFINITION

"""The root query"""
type Query {
  "Album by id; share tokens may read it"
  album(id: ID!, tokenCredentials: ShareTokenCredentials): Album!
  myAlbums(
    "sort order"
    order: Ordering
    paginate: Pagination
  ): [Album!]! @isAuthorized
  siteInfo: SiteInfo!
}

type Mutation {
  shareAlbum(albumId: ID!, expire: Time, password: String = "x"): ShareToken! @isAuthorized
  deleteUser(id: ID!): User! @isAdmin
}

type Album {
  id: ID!
  title: String!
  shares: [ShareToken!]!
}

extend type Query {
  mapboxToken: String
}
`;

describe('GraphQL schema scan', () => {
  it('reads root types, arguments (descriptions, optional commas, defaults), return types and directives', () => {
    const s = scanGraphql(`schema { query: RootQuery mutation: RootMutation }\n${SCHEMA.replace('type Query', 'type RootQuery').replace('extend type Query', 'extend type RootQuery').replace('type Mutation', 'type RootMutation')}\ntype Secret @isAdmin { key(id: ID!): String }`);
    expect(s.roots).toEqual({ query: 'RootQuery', mutation: 'RootMutation', subscription: 'Subscription' });
    expect(s.types.RootQuery!.map((f) => f.name)).toEqual(['album', 'myAlbums', 'siteInfo', 'mapboxToken']);
    expect(s.types.RootQuery![1]).toEqual({ name: 'myAlbums', args: 'order: Ordering, paginate: Pagination', type: '[Album!]!', directives: ['@isAuthorized'] });
    expect(s.types.RootMutation![0]).toMatchObject({ args: 'albumId: ID!, expire: Time, password: String = ""', type: 'ShareToken!', directives: ['@isAuthorized'] });
    expect(s.types.Album!.map((f) => f.name)).toEqual(['id', 'title', 'shares']);
    expect(s.types.Secret![0]!.directives).toEqual(['@isAdmin']); // type-level directive applies to its fields
  });

  it('flags mutations and id / token arguments as state-changing or by-id', () => {
    expect(graphqlStateOrById('rpc:graphql:Mutation/shareAlbum', 'Mutation.shareAlbum(albumId: ID!)')).toBe(true);
    expect(graphqlStateOrById('rpc:graphql:Query/album', 'Query.album(id: ID!, tokenCredentials: X)')).toBe(true);
    expect(graphqlStateOrById('rpc:graphql:Query/siteInfo', 'Query.siteInfo(): SiteInfo!')).toBe(false);
    expect(graphqlStateOrById('POST /api/x', undefined)).toBe(false);
  });
});

describe('GraphQL resolver entries', () => {
  it('Go gqlgen: root and field resolvers across files, schema directives as auth signals, helpers excluded', async () => {
    const idx = await indexOf({
      'go.mod': 'module example.com/photo\n\ngo 1.22\n',
      'api/graphql/schema.graphql': SCHEMA,
      'api/graphql/resolvers/album.go': `package resolvers

import "context"

func (r *queryResolver) Album(ctx context.Context, id int, tokenCredentials *ShareTokenCredentials) (*Album, error) { return r.DB.Find(id) }
func (r *queryResolver) MyAlbums(ctx context.Context, order *Ordering, paginate *Pagination) ([]*Album, error) { return nil, nil }
func (r *albumResolver) Shares(ctx context.Context, obj *Album) ([]*ShareToken, error) { return nil, nil }
func (r *albumResolver) helper() {}
func (r *albumResolver) Cache(ctx context.Context) {}
`,
      'api/graphql/resolvers/share.go': `package resolvers

import "context"

func (r *mutationResolver) ShareAlbum(ctx context.Context, albumID int, expire *Time, password *string) (*ShareToken, error) { return nil, nil }
func (r *Resolver) Mutation() MutationResolver { return &mutationResolver{r} }
`,
      'internal/dns/resolver.go': `package dns

func (r *hostResolver) Lookup(name string) string { return name }
`,
    });
    expect(gql(idx)).toEqual(['rpc:graphql:Album/shares', 'rpc:graphql:Mutation/shareAlbum', 'rpc:graphql:Query/album', 'rpc:graphql:Query/myAlbums']);
    expect(entry(idx, 'rpc:graphql:Mutation/shareAlbum')).toMatchObject({
      kind: 'rpc', framework: 'gqlgen', ruleId: 'go.gqlgen.operation', pathTemplate: 'Mutation.shareAlbum(albumId: ID!, expire: Time, password: String = ""): ShareToken!',
      middlewares: ['@isAuthorized'], authSignals: ['@isAuthorized'],
    });
    expect(entry(idx, 'rpc:graphql:Mutation/shareAlbum').handler).toMatch(/share\.go#resolvers\.mutationResolver\.ShareAlbum\(4\)$/);
    expect(entry(idx, 'rpc:graphql:Mutation/shareAlbum').httpMethod).toBeUndefined();
    expect(entry(idx, 'rpc:graphql:Query/album').authSignals).toEqual([]); // public
    expect(entry(idx, 'rpc:graphql:Album/shares')).toMatchObject({ ruleId: 'go.gqlgen.field', pathTemplate: 'Album.shares(): [ShareToken!]!' });
  });

  it('Go without a schema: `…Resolver` methods are not GraphQL entries', async () => {
    const idx = await indexOf({
      'go.mod': 'module example.com/x\n\ngo 1.22\n',
      'r.go': 'package x\n\nimport "context"\n\nfunc (r *queryResolver) Album(ctx context.Context, id int) error { return nil }\n',
    });
    expect(gql(idx)).toEqual([]);
  });

  it('Java: Spring for GraphQL, DGS and kickstart resolvers; method security and schema directives', async () => {
    const idx = await indexOf({
      'src/main/resources/graphql/schema.graphqls': SCHEMA,
      'src/main/java/photo/AlbumController.java': `package photo;
@Controller
public class AlbumController {
    @QueryMapping
    public Album album(@Argument Long id) { return repo.findById(id); }
    @MutationMapping(name = "shareAlbum")
    @PreAuthorize("isAuthenticated()")
    public ShareToken share(@Argument Long albumId) { return null; }
    @SchemaMapping(typeName = "Album", field = "shares")
    public List<ShareToken> shares(Album album) { return null; }
    @QueryMapping
    public String notInSchema() { return ""; }
}
`,
      'src/main/java/photo/AdminFetcher.java': `package photo;
@DgsComponent
public class AdminFetcher {
    @DgsMutation
    public User deleteUser(@InputArgument Long id) { return null; }
    @DgsData(parentType = "Query", field = "siteInfo")
    public SiteInfo info() { return null; }
    @DgsData(parentType = DgsConstants.ALBUM.TYPE_NAME, field = DgsConstants.ALBUM.Shares)
    public List<ShareToken> albumShares(DgsDataFetchingEnvironment env) { return null; }
}
`,
      'src/main/java/photo/AlbumResolver.java': `package photo;
public class AlbumResolver implements GraphQLResolver<Album> {
    public String getTitle(Album a) { return a.title; }
}
`,
      'src/main/java/photo/RootQuery.java': `package photo;
public class RootQuery implements GraphQLQueryResolver {
    public String mapboxToken() { return token; }
}
`,
    });
    expect([...new Set(gql(idx))]).toEqual([
      'rpc:graphql:Album/shares', 'rpc:graphql:Album/title', 'rpc:graphql:Mutation/deleteUser', 'rpc:graphql:Mutation/shareAlbum',
      'rpc:graphql:Query/album', 'rpc:graphql:Query/mapboxToken', 'rpc:graphql:Query/siteInfo',
    ]);
    expect(entry(idx, 'rpc:graphql:Mutation/shareAlbum')).toMatchObject({ framework: 'graphql', ruleId: 'java.spring-graphql.operation', middlewares: ['@isAuthorized'] });
    expect(entry(idx, 'rpc:graphql:Mutation/shareAlbum').authSignals).toEqual(expect.arrayContaining(['@PreAuthorize("isAuthenticated()")', '@isAuthorized']));
    expect(entry(idx, 'rpc:graphql:Mutation/deleteUser')).toMatchObject({ ruleId: 'java.dgs.operation', authSignals: ['@isAdmin'] });
    expect(entry(idx, 'rpc:graphql:Album/title').handler).toMatch(/AlbumResolver\.getTitle\(1\)$/);
    // DGS generated constants resolve against the schema's spelling.
    expect(idx.entrypoints.filter((e) => e.entryKey === 'rpc:graphql:Album/shares').map((e) => e.ruleId).sort()).toEqual(['java.dgs.field', 'java.spring-graphql.field']);
  });

  it('JS / TS: resolver maps (schema in a gql template), exported root objects, NestJS decorators with guards', async () => {
    const idx = await indexOf({
      'package.json': '{"name":"photo","dependencies":{"@apollo/server":"4.0.0","@nestjs/graphql":"12.0.0"}}',
      'src/schema.js': `import { gql } from 'graphql-tag';
export const typeDefs = gql\`
  type Query { album(id: ID!): Album  albums: [Album!]! @auth }
  type Mutation { shareAlbum(albumId: ID!): ShareToken @auth }
  type Album { id: ID! shares: [ShareToken!]! }
\`;
`,
      'src/resolvers.js': `import { listAlbums } from './albums.js';
export const resolvers = {
  Query: {
    album: (_, { id }, ctx) => ctx.db.album(id),
    albums: listAlbums,
  },
  Album: {
    async shares(album, _, ctx) { return ctx.db.shares(album.id); },
  },
  Scalar: { serialize: (v) => v },
};
`,
      'src/albums.js': 'export function listAlbums() { return []; }\n',
      'src/mutation.ts': `export const Mutation = {
  shareAlbum: async (_: unknown, args: { albumId: string }) => share(args.albumId),
};
`,
      'src/album.resolver.ts': `import { Resolver, Query, Mutation, ResolveField, Parent } from '@nestjs/graphql';
import { UseGuards } from '@nestjs/common';
@Resolver(() => Album)
export class AlbumResolver {
  @Query(() => Album, { name: 'album' })
  findOne(id: string) { return this.svc.find(id); }
  @UseGuards(GqlAuthGuard)
  @Mutation(() => ShareToken)
  shareAlbum(albumId: string) { return null; }
  @ResolveField('shares')
  sharesOf(@Parent() album: Album) { return []; }
}
`,
      'src/users.controller.ts': `import { Controller, Get, Query } from '@nestjs/common';
@Controller('users')
export class UsersController {
  @Get()
  list(@Query() q: any) { return []; }
}
`,
    });
    const keys = gql(idx);
    expect(keys.filter((k, i) => keys.indexOf(k) === i)).toEqual(['rpc:graphql:Album/shares', 'rpc:graphql:Mutation/shareAlbum', 'rpc:graphql:Query/album', 'rpc:graphql:Query/albums']);
    const map = idx.entrypoints.filter((e) => e.ruleId.startsWith('js.graphql.resolver-map'));
    expect(map.map((e) => e.entryKey).sort()).toEqual(['rpc:graphql:Album/shares', 'rpc:graphql:Mutation/shareAlbum', 'rpc:graphql:Query/album', 'rpc:graphql:Query/albums']);
    expect(map.find((e) => e.entryKey === 'rpc:graphql:Query/albums')!.handler).toMatch(/albums\.js#.*listAlbums\(0\)$/);
    expect(map.find((e) => e.entryKey === 'rpc:graphql:Query/albums')!.authSignals).toEqual(['@auth']);
    const nest = idx.entrypoints.filter((e) => e.ruleId.startsWith('js.graphql.decorator'));
    expect(nest.map((e) => e.entryKey).sort()).toEqual(['rpc:graphql:Album/shares', 'rpc:graphql:Mutation/shareAlbum', 'rpc:graphql:Query/album']);
    expect(nest.find((e) => e.entryKey === 'rpc:graphql:Mutation/shareAlbum')!.authSignals).toEqual(expect.arrayContaining(['@UseGuards(GqlAuthGuard)', '@auth']));
    expect(nest.find((e) => e.entryKey === 'rpc:graphql:Query/album')!.handler).toMatch(/AlbumResolver\.findOne\(1\)$/);
  });
});
