<?php

namespace Drupal\graphql_jwt_login;

use Drupal\jwt\Authentication\Provider\JwtAuth;
use Drupal\jwt\Transcoder\JwtTranscoderInterface;
use Drupal\jwt\Transcoder\JwtTranscoder;
use Drupal\jwt\Authentication\Event\JwtAuthGenerateEvent;
use Drupal\jwt\Authentication\Event\JwtAuthEvents;
use Drupal\jwt\JsonWebToken\JsonWebToken;
use Firebase\JWT\JWT;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\key\KeyRepositoryInterface;
use Drupal\user\UserAuthInterface;
use Drupal\Core\Flood\FloodInterface;
use Drupal\Core\Entity\EntityManagerInterface;

class LoginManager {

  const ERROR = 'ERROR: The credentials provided could not be authenticated';
  /**
   * The config factory.
   *
   * @var \Drupal\Core\Config\ConfigFactoryInterface
   */
  protected $configFactory;

  /**
   * The user auth service.
   *
   * @var \Drupal\user\UserAuthInterface
   */
  protected $userAuth;

  /**
   * The flood service.
   *
   * @var \Drupal\Core\Flood\FloodInterface
   */
  protected $flood;

  /**
   * The entity manager.
   *
   * @var \Drupal\Core\Entity\EntityManagerInterface
   */
  protected $entityManager;

  /**
   * The JWT Transcoder service.
   *
   * @var \Drupal\jwt\Transcoder\JwtTranscoderInterface
   */
  protected $transcoder;

  /**
   * The event dispatcher.
   *
   * @var \Symfony\Component\EventDispatcher\EventDispatcherInterface
   */
  protected $eventDispatcher;

  /**
   * The JWT Auth.
   *
   * @var \Drupal\jwt\Authentication\Provider\JwtAuth
   */
  protected $jwtAuth = NULL;


  /**
   * Constructs a SigningUtility object.
   *
   * @param JwtAuth $jwtAuth
   * @param EventDispatcherInterface $eventDispatcher
   * @param ConfigFactoryInterface $configFactory
   * @param KeyRepositoryInterface $keyRepository
   * @param UserAuthInterface $userAuth
   * @param FloodInterface $flood
   * @param EntityManagerInterface $entityManager
   */
  public function __construct(
    JwtAuth $jwtAuth,
    EventDispatcherInterface $eventDispatcher,
    ConfigFactoryInterface $configFactory,
    KeyRepositoryInterface $keyRepository,
    UserAuthInterface $userAuth,
    FloodInterface $flood,
    EntityManagerInterface $entityManager
  ) {
    $this->jwtAuth = $jwtAuth;
    $this->eventDispatcher = $eventDispatcher;
    $this->configFactory = $configFactory;
    $this->userAuth = $userAuth;
    $this->flood = $flood;
    $this->entityManager = $entityManager;
    $this->transcoder = new JwtTranscoder(new JWT(), $configFactory, $keyRepository);
  }

  /**
   * {@inheritdoc}
   */
  public static function create($jwtAuth, $eventDispatcher, $configFactory, $keyRepository, $userAuth, $flood, $entityManager) {
    return new static($jwtAuth, $eventDispatcher, $configFactory, $keyRepository, $userAuth, $flood, $entityManager);
  }

  /**
   * Validate and return a jwt token.
   *
   * @param string $username
   *   The username.
   * @param string $password
   *   The password.
   *
   * @return array
   *   The jwt key.
   * @throws \Drupal\Component\Plugin\Exception\InvalidPluginDefinitionException
   */
  public function authenticate($username, $password) {

    $flood_config = $this->configFactory->getEditable('user.flood');

    // Flood protection: this is very similar to the user login form code.
    // @see \Drupal\user\Form\UserLoginForm::validateAuthentication()
    // Do not allow any login from the current user's IP if the limit has been
    // reached. Default is 50 failed attempts allowed in one hour. This is
    // independent of the per-user limit to catch attempts from one IP to log
    // in to many different user accounts.  We have a reasonably high limit
    // since there may be only one apparent IP for all users at an institution.
    if ($this->flood->isAllowed('graphql_auth.failed_login_ip', $flood_config->get('ip_limit'), $flood_config->get('ip_window'))) {
      $accounts = $this->entityManager->getStorage('user')->loadByProperties(['name' => $username, 'status' => 1]);
      $account = reset($accounts);
      if ($account) {
        if ($flood_config->get('uid_only')) {
          // Register flood events based on the uid only, so they apply for any
          // IP address. This is the most secure option.
          $identifier = $account->id();
        }
        else {
          // The default identifier is a combination of uid and IP address. This
          // is less secure but more resistant to denial-of-service attacks that
          // could lock out all users with public user names.
          $identifier = $account->id() . '-' . \Drupal::request()->getClientIP();
        }
        // Don't allow login if the limit for this user has been reached.
        // Default is to allow 5 failed attempts every 6 hours.
        if ($this->flood->isAllowed('graphql_auth.failed_login_user', $flood_config->get('user_limit'), $flood_config->get('user_window'), $identifier)) {
          $uid = $this->userAuth->authenticate($username, $password);
          if ($uid) {
            $this->flood->clear('graphql_auth.failed_login_user', $identifier);
            $event = new JwtAuthGenerateEvent(new JsonWebToken());
            $this->eventDispatcher->dispatch(JwtAuthEvents::GENERATE, $event);
            $jwt = $event->getToken();
            return [
              'key' => $this->transcoder->encode($jwt),
              'error' => 'null'
            ];
          }
          else {
            // Register a per-user failed login event.
            $this->flood->register('graphql_auth.failed_login_user', $flood_config->get('user_window'), $identifier);
            return [
              'key' => 'null',
              'error' => LoginManager::ERROR
            ];
          }
        }
      }
    }
    // Always register an IP-based failed login event.
    $this->flood->register('graphql_auth.failed_login_ip', $flood_config->get('ip_window'));
    return [
      'key' => 'null',
      'error' => LoginManager::ERROR
    ];

  }

}