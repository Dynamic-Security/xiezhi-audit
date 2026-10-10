(scoped_call_expression
  scope: (_) @receiver
  name: (name) @method
  arguments: (arguments) @args
  (#match? @method "^(select|selectOne|insert|update|delete|statement|unprepared|raw|affectingStatement|cursor|scalar)$")) @call
