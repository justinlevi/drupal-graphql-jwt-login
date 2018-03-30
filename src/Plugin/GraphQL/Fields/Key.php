<?php

namespace Drupal\graphql_jwt_login\Plugin\GraphQL\Fields;

use Drupal\graphql\GraphQL\Execution\ResolveContext;
use Drupal\graphql\Plugin\GraphQL\Fields\FieldPluginBase;
use GraphQL\Type\Definition\ResolveInfo;

/**
 * A jwt key.
 *
 * @GraphQLField(
 *   id = "key",
 *   secure = true,
 *   name = "key",
 *   type = "String",
 *   parents = {"Jwt"}
 * )
 */
class Key extends FieldPluginBase {

  /**
   * {@inheritdoc}
   */
  public function resolveValues($value, array $args, ResolveContext $context, ResolveInfo $info) {
    yield $value['key'];
  }

}
