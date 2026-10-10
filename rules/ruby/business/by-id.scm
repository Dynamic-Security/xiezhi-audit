(call
  receiver: (_) @receiver
  method: (_) @method
  (#match? @method "^(find|find_by|find_by!|find_by_id|find_by_id!|find_by_uuid|find_by_slug|find_by_slug!)$")) @call
