<?php

namespace Drupal\graphql_jwt_login\Plugin\GraphQL\Fields;

use Drupal\Core\DependencyInjection\DependencySerializationTrait;
use Drupal\Core\Plugin\ContainerFactoryPluginInterface;
use Drupal\graphql\Plugin\GraphQL\Fields\FieldPluginBase;
use Drupal\graphql_jwt_login\LoginManager;
use GraphQL\Type\Definition\ResolveInfo;
use Drupal\graphql\GraphQL\Execution\ResolveContext;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Drupal\graphql_jwt_login\Plugin\GraphQL\Types\Jwt;

/**
 * Login
 *
 * @GraphQLField(
 *   id = "login",
 *   secure = true,
 *   name = "login",
 *   type = "Jwt",
 *   response_cache_max_age = 0,
 *   arguments = {
 *      "input" = "LoginInput"
 *   }
 * )
 */
class Login extends FieldPluginBase implements ContainerFactoryPluginInterface {

  use DependencySerializationTrait;

  /**
   * The page instance.
   *
   * @var \Drupal\graphql_jwt_login\LoginManager
   */
  protected $loginManager;

  /**
   * {@inheritdoc}
   */
  public function resolveValues($value, array $args, ResolveContext $context, ResolveInfo $info) {
    $result = $this->loginManager->authenticate($args['input']['username'], $args['input']['password']);
    yield $result;
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container, array $configuration, $pluginId, $pluginDefinition) {

    /** @var \Drupal\graphql_jwt_login\LoginManager $loginManager */
    $loginManager = $container->get('graphql_jwt_login.login_manager');

    return new static(
      $configuration,
      $pluginId,
      $pluginDefinition,
      $loginManager
    );
  }

  /**
   * Constructs a Drupal\Component\Plugin\PluginBase object.
   *
   * @param array $configuration
   *   A configuration array containing information about the plugin instance.
   * @param $pluginId
   * @param $pluginDefinition
   * @param \Drupal\graphql_jwt_login\LoginManager $loginManager
   */
  public function __construct(array $configuration, $pluginId, $pluginDefinition, $loginManager) {
    $this->loginManager = $loginManager;
    parent::__construct($configuration, $pluginId, $pluginDefinition);
  }

}
