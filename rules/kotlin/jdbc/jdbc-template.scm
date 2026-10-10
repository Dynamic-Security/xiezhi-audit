(call_expression
  (navigation_expression . (_) @receiver (identifier) @method .)
  (value_arguments) @args
  (#match? @method "^(query|queryForObject|queryForList|queryForMap|queryForRowSet|queryForStream|update|execute|batchUpdate)$")) @call
