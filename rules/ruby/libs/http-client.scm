(call
  receiver: (_) @receiver
  method: (identifier) @method
  (#match? @method "^(get|get_response|get_print|post|post_form|put|patch|delete|head|options|start|new|request|execute|open|open_uri|fetch)$")) @call
