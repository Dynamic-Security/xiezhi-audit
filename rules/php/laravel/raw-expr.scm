(member_call_expression
  object: (_) @receiver
  name: (name) @method
  arguments: (arguments) @args
  (#match? @method "^(whereRaw|orWhereRaw|orderByRaw|selectRaw|havingRaw|orHavingRaw|groupByRaw|fromRaw)$")) @call
(nullsafe_member_call_expression
  object: (_) @receiver
  name: (name) @method
  arguments: (arguments) @args
  (#match? @method "^(whereRaw|orWhereRaw|orderByRaw|selectRaw|havingRaw|orHavingRaw|groupByRaw|fromRaw)$")) @call
(scoped_call_expression
  scope: (_) @receiver
  name: (name) @method
  arguments: (arguments) @args
  (#match? @method "^(whereRaw|orWhereRaw|orderByRaw|selectRaw|havingRaw|groupByRaw|fromRaw)$")) @call
