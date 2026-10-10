(call
  receiver: (_) @receiver
  method: (identifier) @method
  (#match? @method "^(load|unsafe_load|load_stream|unsafe_load_file|load_file)$")) @call
