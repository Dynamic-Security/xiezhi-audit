(call
  function: (attribute object: (_) @receiver attribute: (identifier) @method)
  arguments: (argument_list) @args
  (#match? @method "^(system|popen|popen2|popen3|execl|execle|execlp|execv|execve|execvp|spawnl|spawnlp|spawnv|spawnvp|getoutput|getstatusoutput|create_subprocess_shell)$")) @call
(call
  function: (identifier) @method
  arguments: (argument_list) @args
  (#match? @method "^(system|popen|getoutput|getstatusoutput)$")) @call
