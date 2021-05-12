<?php
namespace Muvon\Bitclout;
use stdClass;
use BIP\BIP44;
use Muvon\KISS\RequestTrait;
use Muvon\KISS\Base58Codec;

class NodeAPI {
  const NETWORK_PREFIX = 'cd1400';

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
  }

  public static function create(array $config): static {
    return new static($config);
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

  public function getNotifications(): array {
    return $this->run('get-notifications', [
      'PublicKeyBase58Check' => $this->public_key,
      'FetchStartIndex' => -1,
      'NumToFetch' => 50,
    ]);
  }

  public function buyCreatorCoin(string $creator_key, int $value, bool $preview = false): array{
    $response = $this->run('buy-or-sell-creator-coin' . ($preview ? '-preview' : '') . '-WVAzTWpGOFFnMlBvWXZhTFA4NjNSZGNW', [
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
    $response = $this->run('buy-or-sell-creator-coin' . ($preview ? '-preview' : '') . '-WVAzTWpGOFFnMlBvWXZhTFA4NjNSZGNW', [
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
    $response = $this->run('transfer-creator-coin', [
      'SenderPublicKeyBase58Check' => $this->public_key,
      'CreatorPublicKeyBase58Check' => $creator_key,
      'ReceiverUsernameOrPublicKeyBase58Check' => $receiver_key,
      'CreatorCoinToTransferNanos' => $value,
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

  public function run(string $path, array $payload, string $method = 'POST'): array {
    $url = match ($path) {
      'submit-transaction' => $this->write_url,
      default => $this->read_url
    };

    if (!str_starts_with($path, 'api')) {
      $path = 'api/v0/' . $path;
    }

    [$err, $result] = $this->request($url . '/' . $path, $payload, $method);
    if ($err) {
      return [$err, null];
    }

    return [$err, $result];
  }
}
