(invocation_expression
  function: (member_access_expression
    expression: (_) @receiver
    name: [(identifier) @method (generic_name (identifier) @method)])
  arguments: (argument_list) @args
  (#match? @method "^(DownloadString|DownloadData|DownloadFile|OpenRead|UploadString|UploadData|UploadValues|DownloadStringTaskAsync|DownloadDataTaskAsync|DownloadFileTaskAsync|OpenReadTaskAsync)$")) @call
