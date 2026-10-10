(call
  receiver: (_) @receiver
  method: (identifier) @method
  (#match? @method "^(find_by_sql|count_by_sql)$")) @call
(call
  !receiver
  method: (identifier) @method
  (#match? @method "^(find_by_sql|count_by_sql)$")) @call
