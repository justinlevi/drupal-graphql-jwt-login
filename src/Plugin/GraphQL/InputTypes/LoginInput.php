<?php

namespace Drupal\graphql_jwt_login\Plugin\GraphQL\InputTypes;

use Drupal\graphql\Plugin\GraphQL\InputTypes\InputTypePluginBase;

/**
 * Login input type.
 *
 * @GraphQLInputType(
 *   id = "login_input",
 *   name = "LoginInput",
 *   fields = {
 *     "username" = "String",
 *     "password" = "String",
 *   }
 * )
 */
class LoginInput extends InputTypePluginBase {

}
