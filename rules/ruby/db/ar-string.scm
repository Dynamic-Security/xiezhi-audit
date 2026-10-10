(call
  receiver: (_) @receiver
  method: (identifier) @method
  (#match? @method "^(where|rewhere|not|or|having|order|reorder|group|pluck|select|from|joins|left_joins|lock|find_by|find_by!|exists\\?|delete_all|update_all|destroy_by|delete_by|calculate|pick|find_or_create_by|find_or_initialize_by|in_order_of)$")) @call
(call
  !receiver
  method: (identifier) @method
  (#match? @method "^(where|rewhere|not|or|having|order|reorder|group|pluck|select|from|joins|left_joins|lock|find_by|find_by!|exists\\?|delete_all|update_all|destroy_by|delete_by|calculate|pick|find_or_create_by|find_or_initialize_by|in_order_of)$")) @call
