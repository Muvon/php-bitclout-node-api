<?php

use Muvon\Bitclout\NodeAPI;
use PHPUnit\Framework\TestCase;

class NodeAPITest extends TestCase {
  protected NodeAPI $node;
  public function setUp(): void {
    $address = NodeAPI::generateAddress();
    $this->node = NodeAPI::create([
      'url' => 'https://api.bitclout.com',
      'mnemonic' => $address['secret']['mnemonic'],
    ]);
  }
  public function testGetProfileByUsername() {
    [$err, $result] = $this->node->getProfile('muvon', 'username');
    $this->assertNull($err);
    $this->assertIsArray($result);
    $this->assertEquals($result['PublicKeyBase58Check'], 'BC1YLfnHSasEiJfSVMoSWVN8h5fXCLSZG9VYGBgFGBhTqEtCxs2LVUL');
  }

  public function testGetProfileByPubkey() {
    [$err, $result] = $this->node->getProfile('BC1YLfnHSasEiJfSVMoSWVN8h5fXCLSZG9VYGBgFGBhTqEtCxs2LVUL', 'pubkey');
    $this->assertNull($err);
    $this->assertIsArray($result);
    $this->assertEquals($result['Username'], 'Muvon');
  }

  public function testGetAddressTransactions() {
    [$err, $result] = $this->node->getPubkeyInfo('BC1YLfnHSasEiJfSVMoSWVN8h5fXCLSZG9VYGBgFGBhTqEtCxs2LVUL');
    $this->assertNull($err);
    $this->assertIsArray($result);
    $this->assertArrayHasKey('Transactions', $result);
    $this->assertIsArray($result['Transactions']);
    $this->assertArrayHasKey('BalanceNanos', $result);
  }
}