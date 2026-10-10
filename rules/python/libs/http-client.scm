(call
  function: (attribute object: (_) @receiver attribute: (identifier) @method)
  arguments: (argument_list) @args
  (#match? @method "^(get|post|put|patch|delete|head|options|request|stream|urlopen|urlretrieve|Request)$")) @call
(call
  function: (identifier) @method
  arguments: (argument_list) @args
  (#match? @method "^(urlopen|urlretrieve)$")) @call
