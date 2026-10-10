(method_declaration
  (attribute_list (attribute name: (_) @ann))
  (#match? @ann "^(Http(Get|Post|Put|Delete|Patch|Head|Options)|Route|AcceptVerbs)(Attribute)?$")) @handler
