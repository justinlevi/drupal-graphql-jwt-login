<?php

namespace Drupal\graphql_jwt_login\Plugin\GraphQL\Fields;

use Drupal\graphql\GraphQL\Execution\ResolveContext;
use Drupal\graphql\Plugin\GraphQL\Fields\FieldPluginBase;
use GraphQL\Type\Definition\ResolveInfo;

/**
 * A jwt key Error.
 *
 * @GraphQLField(
 *   id = "error",
 *   secure = true,
 *   name = "error",
 *   type = "String",
 *   parents = {"Jwt"}
 * )
 */
class Error extends FieldPluginBase {

  /**
   * {@inheritdoc}
   */
  public function resolveValues($value, array $args, ResolveContext $context, ResolveInfo $info) {
    yield $value['error'];
  }

}
