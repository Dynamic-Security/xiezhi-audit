(call
  receiver: (_) @receiver
  method: (identifier) @method
  (#match? @method "^(read|binread|readlines|foreach|open|write|binwrite|delete|unlink|rename|new|copy|copy_file|cp|cp_r|mv|rm|rm_f|rm_r|rm_rf|remove|remove_dir|remove_entry|remove_file|chmod|chown|symlink|ln_s|glob|entries|children|mkdir_p|install|truncate)$")) @call
