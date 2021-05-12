<?php
namespace Muvon\Bitclout;

use Elliptic\EC;

class Signer {
  public static function secp256k1(string $hash, string $key): string {
    $ec = new EC('secp256k1');
    $ecPrivateKey = $ec->keyFromPrivate($key, 'hex');
    $signature = $ecPrivateKey->sign($hash, ['canonical' => true]);

    $r = '';
    foreach ($signature->toDER() as $chr) {
      $r .= chr($chr);
    }
    return bin2hex($r);
  }
}