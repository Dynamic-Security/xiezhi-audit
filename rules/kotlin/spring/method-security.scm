(annotation
  [(user_type (identifier) @ann) (constructor_invocation (user_type (identifier) @ann))]
  (#match? @ann "^(PreAuthorize|PostAuthorize|Secured|RolesAllowed|RequiresPermissions|RequiresRoles|SaCheckLogin|SaCheckPermission|SaCheckRole)$")) @annotation
