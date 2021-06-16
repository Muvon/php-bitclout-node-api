<?php
namespace Muvon\Bitclout;
use stdClass;
use BIP\BIP44;
use Muvon\KISS\RequestTrait;
use Muvon\KISS\Base58Codec;

class NodeAPI {
  const NETWORK_PREFIX = 'cd1400';
  const HD_PATH = "m/44'/0'/0'/0/0";

  protected array $useragents = [];
  protected array $proxies = [];
  protected array $proxy_modes = ['read', 'write'];

  use RequestTrait;

  public function __construct(array $config) {
    $this->request_type = 'json';
    $this->request_connect_timeout = 10;
    $this->request_timeout = 30;
    $this->read_url = $config['read_url'] ?? $config['url'];
    $this->write_url = $config['write_url'] ?? $config['url'];
    $this->min_rate_nanos = intval($config['min_fee'] ?? 1000);
    if (isset($config['mnemonic'])) {
      $seed = BIP39::mnemonicToSeedHex($config['mnemonic'], '');
      $HDKey = BIP44::fromMasterSeed($seed)->derive("m/44'/0'/0'/0/0");
      $this->private_key = $HDKey->privateKey;
      $this->public_key = Base58Codec::checkEncode(static::NETWORK_PREFIX . $HDKey->publicKey);
    } else {
      $this->private_key = $config['private_key'];
      $this->public_key = $config['public_key'];
    }

    if (isset($config['proxies'])) {
      $this->proxies = array_map(function ($v): array {
        if (is_string($v)) {
          [$type, $host, $port, $user, $password] = explode(':', $v);
          $proxy = compact('type', 'host', 'port', 'user', 'password');
        } else {
          $proxy = $v;
        }

        return $proxy;
      }, $config['proxies']);
    }

    if (isset($config['proxy_modes'])) {
      $this->proxy_modes = $config['proxy_modes'];
    }

    if (isset($config['useragents'])) {
      $this->useragents = $config['useragents'];
    }
  }

  public static function create(array $config): static {
    return new static($config);
  }

  public static function generateAddress(): array {
    $entropy = BIP39::generateEntropy(128);
    $mnemonic = BIP39::entropyToMnemonic($entropy);
    $seed = BIP39::mnemonicToSeedHex($mnemonic, '');
    $HDKey = BIP44::fromMasterSeed($seed)->derive(static::HD_PATH);
    $address = Base58Codec::checkEncode(static::NETWORK_PREFIX . $HDKey->publicKey);
    return [
      'address' => $address,
      'public' => $HDKey->publicKey,
      'secret' => [
        'private' => $HDKey->privateKey,
        'seed' => $seed,
        'mnemonic' => $mnemonic,
      ]
    ];
  }

  public function getLastBlock(): array {
    return $this->run('api/v1', [], 'GET');
  }

  public function getBlock(int|string $search, string $type = 'height', bool $is_full = false): array {
    return $this->run('api/v1/block', [
      'Height' => $type === 'height' ? intval($search) : null,
      'HashHex' => $type === 'hash' ? $search : null,
      'FullBlock' => $is_full,
    ]);
  }

  public function getMempool(): array {
    return $this->run('api/v1/transaction-info', [
      'IsMempool' => true,
    ]);
  }

  public function getTransaction(string $id): array {
    return $this->run('api/v1/transaction-info', [
      'TransactionIDBase58Check' => $id,
    ]);
  }

  public function getPubkeyInfo(string $pubkey): array {
    return $this->run('api/v1/transaction-info', [
      'PublicKeyBase58Check' => $pubkey,
    ]);
  }

  public function getPubkeyBalance(string $pubkey): array {
    return $this->run('api/v1/balance', [
      'PublicKeyBase58Check' => $pubkey,
    ]);
  }

  public function getUserByPublicKey(string $pubkey): array {
    [$err, $result] = $this->run('get-users-stateless', [
      'PublicKeysBase58Check' => [$pubkey]
    ]);
    if ($err) {
      return [$err, null];
    }

    return [null, $result['UserList'][0]];
  }

  public function getProfile(string $search, string $type = 'username'): array {
    [$err, $result] = $this->run('get-single-profile', [
      'Username' => $type === 'username' ? $search : '',
      'PublicKeyBase58Check' => $type === 'pubkey' ? $search : '',
    ]);

    if ($err) {
      return [$err, $result];
    }
    
    return [null, $result['Profile']];
  }

  public function getProfilePic(string $pubkey): string {
    $old_rt = $this->request_type;
    $this->request_type = 'raw';
    [$err, $result] = $this->run('get-single-profile-picture/' . $pubkey, [], 'GET');
    $this->request_type = $old_rt;

    if ($err) {
      return '';
    }
    return 'data:image/webp;base64,' . base64_encode($result);
  }

  public function getProfiles(string $search, string $type = 'username', int $limit = 20, string $order = 'newest', string $moderation = 'unrestricted'): array {
    return $this->run('get-profiles', [
      'PublicKeyBase58Check' => $type === 'pubkey' ? $search : '',
      'Username' => $type === 'username' ? $search : '',
      'UsernamePrefix' => $type === 'prefix' ? $search : '',
      'Description' => '',
      'OrderBy' => $order,
      'ModerationType' => $moderation,
      'FetchUsersThatHODL' => false,
      'AddGlobalFeedBool' => false,
      'NumToFetch' => $limit,
    ]);
  }

  public function getPost(string $hash, int $offset = 0, int $limit = 20): array {
    return $this->run('get-single-post', [
      'PostHashHex' => $hash,
      'ReaderPublicKeyBase58Check' => $this->public_key,
      'FetchParents' => true,
      'CommentOffset' => $offset,
      'CommentLimit' => $limit,
      'AddGlobalFeedBool' => false,
    ]);
  }

  public function getPosts(string $hash = '', ?int $ts = null, int $limit = 50): array {
    [$err, $result] = $this->run('get-posts-stateless', [
      'PostHashHex' => $hash,
      'ReaderPublicKeyBase58Check' => $this->public_key,
      'StartTstampSecs' => $ts,
      'FetchSubcomments' => false,
      'GetPostsForFollowFeed' => false,
      'GetPostsForGlobalWhitelist' => false,
      'GetPostsByClout' => false,
      'PostsByCloutMinutesLookback' => 0,
      'AddGlobalFeedBool' => false,
      'OrderBy' => 'newest',
      'NumToFetch' => $limit
    ]);
    if ($err) {
      return [$err, $result];
    }

    return [null, $result['PostsFound']];
  }

  public function getAccountPosts(string $search, string $type = 'pubkey', int $limit = 10): array {
    return $this->run('get-posts-for-public-key', [
      'PublicKeyBase58Check' => $type === 'pubkey' ? $search : '',
      'Username' => $type === 'username' ? $search : '',
      'ReaderPublicKeyBase58Check' => $this->public_key,
      'LastPostHashHex' => '',
      'NumToFetch' => $limit,
    ]);
  }


  public function likePost(string $hash, $is_unlike = false): array {
    $response = $this->run('create-like-stateless', [
      'IsUnlike' => $is_unlike,
      'LikedPostHashHex' => $hash,
      'MinFeeRateNanosPerKB' => $this->min_rate_nanos,
      'ReaderPublicKeyBase58Check' => $this->public_key,
    ]);
    return $this->signAndSubmitResponse($response);
  }

  public function unlikePost(string $hash): array {
    return $this->likePost($hash, true);
  }

  public function follow(string $pubkey, $is_unfollow = false): array {
    $response = $this->run('create-follow-txn-stateless', [
      'InUnfollow' => $is_unfollow,
      'MinFeeRateNanosPerKB' => $this->min_rate_nanos,
      'FollowerPublicKeyBase58Check' => $this->public_key,
      'FollowedPublicKeyBase58Check' => $pubkey,
    ]);
    return $this->signAndSubmitResponse($response);
  }

  public function unfollow(string $pubkey): array {
    return $this->follow($pubkey, true);
  }

  public function getNotifications(): array {
    return $this->run('get-notifications', [
      'PublicKeyBase58Check' => $this->public_key,
      'FetchStartIndex' => -1,
      'NumToFetch' => 50,
    ]);
  }

  public function buyCreatorCoin(string $creator_key, int $value, bool $preview = false): array{
    $response = $this->run('buy-or-sell-creator-coin', [
      'UpdaterPublicKeyBase58Check' => $this->public_key,
      'CreatorPublicKeyBase58Check' => $creator_key,
      'BitCloutToSellNanos' => $value,
      'CreatorCoinToSellNanos' => 0,
      'BitCloutToAddNanos' => 0,
      'MinBitCloutExpectedNanos' => 0,
      'MinCreatorCoinExpectedNanos' => 0,
      'MinFeeRateNanosPerKB' => $this->min_rate_nanos,
      'OperationType' => 'buy',
    ]);

    if ($preview) {
      return $response;
    }

    return $this->signAndSubmitResponse($response);
  }

  public function sellCreatorCoin(string $creator_key, int $value, bool $preview = false): array{
    $response = $this->run('buy-or-sell-creator-coin', [
      'UpdaterPublicKeyBase58Check' => $this->public_key,
      'CreatorPublicKeyBase58Check' => $creator_key,
      'BitCloutToSellNanos' => 0,
      'CreatorCoinToSellNanos' => $value,
      'BitCloutToAddNanos' => 0,
      'MinBitCloutExpectedNanos' => 0,
      'MinCreatorCoinExpectedNanos' => 0,
      'MinFeeRateNanosPerKB' => $this->min_rate_nanos,
      'OperationType' => 'sell',
    ]);

    if ($preview) {
      return $response;
    }

    return $this->signAndSubmitResponse($response);
  }

  public function getHolders(string $search, string $type = 'username', string $last_pubkey = '', int $limit = 100): array {
    [$err, $result] = $this->run('get-hodlers-for-public-key', [
      'PublicKeyBase58Check' => $type === 'pubkey' ? $search : '',
      'Username' => $type === 'username' ? $search : '',
      'LastPublicKeyBase58Check' => $last_pubkey,
      'NumToFetch' => $limit,
      'FetchHodlings' => false,
      'FetchAll' => $limit === -1 ? true : false,
    ]);

    if ($err) {
      return [$err, $result];
    }

    return [null, $result];
  }

  public function createSendBitcloutTx(string $receiver_key, int $value): array {
    return $this->run('send-bitclout', [
      'SenderPublicKeyBase58Check' => $this->public_key,
      'RecipientPublicKeyOrUsername' => $receiver_key,
      'AmountNanos' => $value,
      'MinFeeRateNanosPerKB' => $this->min_rate_nanos,
    ]);
  }

  public function createSendCreatorCoinTx(string $creator_key, string $receiver_key, int $value): array {
    return $this->run('transfer-creator-coin', [
      'SenderPublicKeyBase58Check' => $this->public_key,
      'CreatorPublicKeyBase58Check' => $creator_key,
      'ReceiverUsernameOrPublicKeyBase58Check' => $receiver_key,
      'CreatorCoinToTransferNanos' => $value,
      'MinFeeRateNanosPerKB' => $this->min_rate_nanos,
    ]);
  }

  public function submitTx(string $signed_tx): array {
    return $this->run('submit-transaction', [
      'TransactionHex' => $signed_tx,
    ]);
  }

  public function signAndSubmitTx(string $raw): array {
    $signed_tx = static::signTransaction($raw, $this->private_key);
    return $this->run('submit-transaction', [
      'TransactionHex' => $signed_tx,
    ]);
  }

  public function sendBitclout(string $receiver_key, int $value): array {
    $response = $this->createSendBitcloutTx($receiver_key, $value);
    return $this->signAndSubmitResponse($response);
  }

  public function sendCreatorCoin(string $creator_key, string $receiver_key, int $value): array {
    $response = $this->createSendCreatorCoinTx($creator_key, $receiver_key, $value);
    return $this->signAndSubmitResponse($response);
  }

  public function sendDiamonds(string $receiver_key, string $post_hash, int $level = 1): array {
    $response = $this->run('send-diamonds', [
      'SenderPublicKeyBase58Check' => $this->public_key,
      'ReceiverPublicKeyBase58Check' => $receiver_key,
      'DiamondPostHashHex' => $post_hash,
      'DiamondLevel' => $level,
      'MinFeeRateNanosPerKB' => $this->min_rate_nanos,
    ]);

    return $this->signAndSubmitResponse($response);
  }

  public function sendMessage(string $receiver_key, string $text): array {
    $response = $this->run('send-message-stateless', [
      'SenderPublicKeyBase58Check' => $this->public_key,
      'RecipientPublicKeyBase58Check' => $receiver_key,
      'MessageText' => $text,
      'MinFeeRateNanosPerKB' => $this->min_rate_nanos,
    ]);

    return $this->signAndSubmitResponse($response);
  }

  public function submitPost(string $text): array {
    $response = $this->run('submit-post', [
      'UpdaterPublicKeyBase58Check' => $this->public_key,
      'PostHashHexToModify' => '',
      'ParentStakeID' => '',
      'Title' => '',
      'BodyObj' => [
        'Body' => $text,
        'ImageURLs' => [],
        'Images' => [],
      ],
      'RecloutedPostHashHex' => '',
      'PostExtraData' => new stdClass,
      'Sub' => '',
      'CreatorBasisPoints' => 0,
      'StakeMultipleBasisPoints' => 12500,
      'IsHidden' => false,
      'MinFeeRateNanosPerKB' => $this->min_rate_nanos,
    ]);
    return $this->signAndSubmitResponse($response);
  }

  protected function signAndSubmitResponse(array $response): array {
    [$err, $result] = $response;
    if ($err) {
      return [$err, $result];
    }
    
    return $this->signAndSubmitTx($result['TransactionHex']);
  }

  public static function getTxHashHex(string $raw): string {
    return hash('sha256', hash('sha256', hex2bin($raw), true));
  }

  public function sign(string $raw): string {
    return static::signTransaction($raw, $this->private_key);
  }

  protected static function signTransaction(string $tx, string $key): string {
    $hash = static::getTxHashHex($tx);
    $signature = Signer::secp256k1($hash, $key);
    return substr($tx, 0, -2) . bin2hex(pack("c", strlen($signature) / 2)) . $signature;
  }

  public function getDiamondsForPublicKey(string $pubkey): array {
    return $this->run('get-diamonds-for-public-key', [
      'PublicKeyBase58Check' => $pubkey
    ]);
  }

  public function getFollowers(string $search, $type = 'pubkey', string $last_pubkey = '', int $limit = 50): array  {
    return $this->run('get-follows-stateless',  [
      'Username' => $type === 'username' ? $search : '',
      'PublicKeyBase58Check' => $type === 'pubkey' ? $search : '',
      'GetEntriesFollowingUsername' => true,
      'LastPublicKeyBase58Check' => $last_pubkey,
      'NumToFetch' => $limit,
    ]);
  }

  public function getFollowing(string $search, $type = 'pubkey', string $last_pubkey = '', int $limit = 50): array  {
    return $this->run('get-follows-stateless',  [
      'Username' => $type === 'username' ? $search : '',
      'PublicKeyBase58Check' => $type === 'pubkey' ? $search : '',
      'GetEntriesFollowingUsername' => false,
      'LastPublicKeyBase58Check' => $last_pubkey,
      'NumToFetch' => $limit,
    ]);
  }

  public function getDiamonds(string $pubkey, bool $is_given = false): array {
    return $this->run('get-diamonds-for-public-key', [
      'FetchYouDiamonded' => $is_given,
      'PublicKeyBase58Check' => $pubkey,
    ]);
  }

  public function getExchangeRate(): array {
    return $this->run('get-exchange-rate', [], 'GET');
  }

  public function run(string $path, array $payload, string $method = 'POST'): array {
    $mode = match ($path) {
      'buy-or-sell-creator-coin', 'create-follow-txn-stateless',
        'create-like-txn-stateless', 'send-diamonds',
        'send-bitclout', 'transfer-creator-coin',
        'send-message-stateless', 'submit-post',
        'submit-transaction' => 'write',
      default => 'read',
    };

    $url = match ($mode) {
      'write' => $this->write_url,
      'read' => $this->read_url,
    };

    if (!str_starts_with($path, 'api')) {
      $path = 'api/v0/' . $path;
    }

    // If we have set proxies, randomize
    if ($this->proxies && in_array($mode, $this->proxy_modes)) {
      $this->request_proxy = $this->proxies[array_rand($this->proxies)];
    } else {
      $this->request_proxy = [];
    }

    // If we have list of user agents randomize it
    if ($this->useragents) {
      $this->request_useragent = $this->useragents[array_rand($this->useragents)];
    }

    [$err, $result] = $this->request($url . '/' . $path, $payload, $method);
    if ($err) {
      return [$err, null];
    }

    return [$err, $result];
  }
}
