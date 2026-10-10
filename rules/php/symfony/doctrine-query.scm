(member_call_expression
  object: (_) @receiver
  name: (name) @method
  arguments: (arguments) @args
  (#match? @method "^(createQuery|createNativeQuery|executeQuery|executeStatement|executeUpdate|fetchAllAssociative|fetchAssociative|fetchOne|fetchAllNumeric|fetchFirstColumn)$")) @call
(nullsafe_member_call_expression
  object: (_) @receiver
  name: (name) @method
  arguments: (arguments) @args
  (#match? @method "^(createQuery|createNativeQuery|executeQuery|executeStatement|executeUpdate|fetchAllAssociative|fetchAssociative|fetchOne|fetchAllNumeric|fetchFirstColumn)$")) @call
