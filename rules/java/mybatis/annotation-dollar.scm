(annotation
  name: (identifier) @ann
  arguments: (annotation_argument_list) @args
  (#match? @ann "^(Select|Update|Insert|Delete|SelectProvider)$")) @call
