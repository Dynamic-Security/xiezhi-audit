(member_call_expression
  object: (_) @receiver
  name: (name) @method
  arguments: (arguments) @args
  (#match? @method "^(download|file|streamDownload)$")) @call
(nullsafe_member_call_expression
  object: (_) @receiver
  name: (name) @method
  arguments: (arguments) @args
  (#match? @method "^(download|file|streamDownload)$")) @call
(scoped_call_expression
  scope: (_) @receiver
  name: (name) @method
  arguments: (arguments) @args
  (#match? @method "^(get|download|delete|readStream|path|url|exists|put)$")) @call
