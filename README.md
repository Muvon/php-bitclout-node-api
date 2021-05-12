# Bitclout Node API

This package allows to interract with Bitclout node with exposed API

## Installation

To install it just use composer

```sh
composer require muvon/bitclout-node-api
```

## How to use

First of all create install of NodeAPI class

```php
use Muvon\Bitclout\NodeAPI;

$node = NodeAPI::create([
  'read_url' => 'https://api.bitclout.com',
  'write_url' => 'https://api.bitclout.com',
  'mnemonic' => 'your mnemonic of 12 words'
]);

```

Config array description:

- **read_url** - url we use for read api calls;
- **write_url** - url we use for write api calls;
- **url** - you can pass single url for read and write operations if its the same;
- **mnemonic** - main account that used as reader and signer for all requests;
- **private_key** - pass hexed private key if not passed mnemonic;
- **public_key** - required only in case if you use private key as hex. In case you use mnemonic it's derived from it.

## Methods available and instructions to use

### generateAddress(): array

Generate new address and return full info about it

Return value is array with that structur

```json
  {
    "address": "BC1... address",
    "public": "public key in hex format",
    "secret": {
      "private": "private key in hex format of hd path: m/44'/0'/0'/0/0",
      "seed": "main seed derived from 12 words",
      "mnemonic": "12 words mnemnoic",
    }
  }
```

## Tests

- Get profile by username
- Get profile by pubkey
- Get address transactions
