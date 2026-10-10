(call
  receiver: (_) @receiver
  method: (identifier) @method
  (#match? @method "^(system|exec|spawn|popen|popen2|popen2e|popen3|capture2|capture2e|capture3|pipeline|pipeline_r|pipeline_w|pipeline_rw|pipeline_start)$")) @call
