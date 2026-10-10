(call
  function: (attribute object: (_) @receiver attribute: (identifier) @method)
  arguments: (argument_list) @args
  (#match? @method "^(open|remove|unlink|rmtree|copyfile|copy|move|rmdir)$")) @call
(call
  function: (identifier) @method
  arguments: (argument_list) @args
  (#match? @method "^(open)$")) @call
