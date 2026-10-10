(method_invocation
  object: (_) @receiver
  name: (identifier) @method
  arguments: (argument_list) @args
  (#match? @method "^(query|queryForObject|queryForList|queryForMap|queryForRowSet|queryForStream|update|execute|batchUpdate)$")) @call
