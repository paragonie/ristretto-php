# Ristretto (PHP)

[![Build Status](https://github.com/paragonie/ristretto-php/actions/workflows/ci.yml/badge.svg)](https://github.com/paragonie/ristretto-php/actions)
[![Latest Stable Version](https://poser.pugx.org/paragonie/ristretto/v/stable)](https://packagist.org/packages/paragonie/ristretto)
[![Latest Unstable Version](https://poser.pugx.org/paragonie/ristretto/v/unstable)](https://packagist.org/packages/paragonie/ristretto)
[![License](https://poser.pugx.org/paragonie/ristretto/license)](https://packagist.org/packages/paragonie/ristretto)
[![Downloads](https://img.shields.io/packagist/dt/paragonie/ristretto.svg)](https://packagist.org/packages/paragonie/ristretto)

Implements a type-safe API for working with [the Ristretto Group](https://ristretto.group)
in PHP projects.

## Requirements

* **PHP 8.1 or newer**

## Installing

```terminal
composer require paragonie/ristretto
```

## Documentation

There are two basic types: `ScalarValue` and `GroupElement`.

The `ScalarValue` object wraps a big integer between 0 and the order of the Ristretto Group, `L`.

The `GroupElement` object wraps a group element of the Ristretto Group.

If an analogy helps, in the world of Ed25519 and X25519, the `ScalarValue` is your secret key, 
and `GroupElement` is your public key.

For that reason, there are also a `SecretKey` and `PublicKey` class, which contains some
basic helper methods for ease-of-use.

## Usage

You can convert from scalars to group elements with `multBase()`, and then use
`scalarPointMultiply()` to perform a commutative group action (e.g. Diffie-Hellman).

```php
<?php
use ParagonIE\Ristretto\{GroupElement, ScalarValue};

$aliceSecret = ScalarValue::random();
$alicePublic = $aliceSecret->multBase();
$bobSecret = ScalarValue::random();
$bobPublic = $bobSecret->multBase();

// You can perform a similar commutative group action
$aliceToBob = $aliceSecret->scalarPointMultiply($bobPublic);
$bobToAlice = $bobSecret->scalarPointMultiply($alicePublic);
var_dump($aliceToBob->equals($bobToAlice)); // bool(true)
```

Otherwise, most operations are within a given type (GroupElement to GroupElement,
ScalarValue to ScalarValue).

### GroupElement

```php
<?php
use ParagonIE\Ristretto\{GroupElement};

$x = GroupElement::random();
$y = GroupElement::random();

$z = $x->add($y);
$w = $z->sub($y);
var_dump($w->equals($x)); // bool(true)
```

### ScalarValue

## Example

This is a PHP implementation of the [libsodium example protocol](https://libsodium.gitbook.io/doc/advanced/point-arithmetic/ristretto#example).

> Perform a secure two-party computation of `f(x) = p(x)^k`. `x` is the input sent to the second party 
> by the first party after blinding it using a random invertible scalar `r`, and `k` is a secret key
> only known by the second party. `p(x)` is a hash-to-group function.

```php
<?php
use ParagonIE\Ristretto\{GroupElement};

// -------- First party -------- Send blinded p(x)
$x = random_bytes(64);

// Compute px = p(x), a group element derived from x
$px = GroupElement::fromHash($x);

// Compute a = p(x) * g^r
$r = ScalarValue::random();
$gr = $r->multBase();
$a = $px->add($gr);

// -------- Second party -------- Send g^k and a^k
$k = ScalarValue::random();

// Compute v = g^k
$v = $k->multBase();

// Compute b = a^k
$b = $k->scalarPointMultiply($a);

// -------- First party -------- Unblind f(x)
// Compute vir = v^(-r)
$ir = $r->negate();
$vir = $v->scalarPointMultiply($ir);

// Compute f(x) = b * v^(-r) = (p(x) * g^r)^k * (g^k)^(-r)
//              = (p(x) * g)^k * g^(-k) = p(x)^k
$fx = $b->add($vir);

// --------- Correctness testing -----------
// If you knew both p(x) and k, you could calculate it directly.

// Directly calculate p(x)^k with both parties' secrets
$pxk = $px->scalarPointMultiply($k);
var_dump($fx->equals($pxk)); // bool(true)
```

