(call
  receiver: (_) @receiver
  method: (identifier) @method
  (#match? @method "^(load|object_load|load_file)$")) @call
