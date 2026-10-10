(function_call_expression
  function: [(name) (qualified_name)] @fn
  arguments: (arguments)
  (#match? @fn "^\\\\?(add_action|register_rest_route|add_menu_page|add_submenu_page|add_options_page|add_management_page|add_users_page|add_theme_page|add_plugins_page|add_dashboard_page|add_posts_page|add_pages_page|add_media_page|add_comments_page|add_links_page)$")) @call
