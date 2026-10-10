(assignment_expression
  left: [(identifier) @method (member_access_expression expression: (_) @receiver name: (identifier) @method)]
  right: (_) @args
  (#match? @method "^(XmlResolver|DtdProcessing|ProhibitDtd)$")
  (#not-match? @args "^(null|true|DtdProcessing\\.(Prohibit|Ignore))$")) @call
