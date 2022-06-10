<?php
declare(strict_types=1);
namespace ParagonIE\Ristretto\Tests;

use Exception;
use ParagonIE\Ristretto\{
    Ristretto,
    GroupElement,
    PublicKey,
    ScalarValue,
    SecretKey
};
use ParagonIE\HiddenString\HiddenString;
use PHPUnit\Framework\TestCase;
use SodiumException;

/**
 * @covers Ristretto, PublicKey, SecretKey, ScalarValue, GroupElement
 */
class KeyTest extends TestCase
{
    /**
     * @throws SodiumException
     */
    public function testPointArithmetic(): void
    {
        $sk = SecretKey::generate();
        $pk = $sk->getPublicKey();

        $random = ScalarValue::random();
        $r = $random->multBase();

        $added = $pk->add($r);
        $this->assertFalse($added->equals($pk));
        $subbed = $added->sub($r);
        $this->assertTrue($pk->equals($subbed));
    }

    /**
     * @throws Exception
     */
    public function testScalarArithmetic(): void
    {
        // random scalars
        $zero = $this->zero();
        $a = ScalarValue::random();
        $b = ScalarValue::random();
        $r = ScalarValue::random();
        $this->assertNotSame($a->hex(), $zero->hex(), 'RNG failure: a == 0');
        $this->assertNotSame($b->hex(), $zero->hex(), 'RNG failure: b == 0');
        $this->assertNotSame($r->hex(), $zero->hex(), 'RNG failure: r == 0');
        $this->assertNotSame($a->hex(), $b->hex(), 'RNG failure: a == b');
        $this->assertNotSame($a->hex(), $r->hex(), 'RNG failure: a == r');
        $this->assertNotSame($b->hex(), $r->hex(), 'RNG failure: b == r');

        // addition
        $c = $a->add($b);
        $this->assertNotSame($a->hex(), $c->hex(), 'a + b != a');
        // subtraction
        $d = $c->sub($b);
        $this->assertSame($a->hex(), $d->hex(), 'a + b - b == a');
        // negation
        $e = $c->add($b->negate());
        $this->assertSame($a->hex(), $e->hex(), 'a + b + (-b) == a');
        // multiplication
        $ar = $a->mul($r);
        $br = $b->mul($r);
        $this->assertNotSame($ar->hex(), $br->hex(), 'given (a != b):  a * r != b * r');
        // multiplicative inverse
        $ir = $r->invert();
        $x = $ar->mul($ir);
        $y = $br->mul($ir);
        $this->assertNotSame($x->hex(), $y->hex(), 'x != y');
        $this->assertSame($a->hex(), $x->hex(), 'a * r * 1/r == a');
        $this->assertSame($b->hex(), $y->hex(), 'b * r * 1/r == b');
        // complements
        $xc = $x->complement();
        $yc = $y->complement();
        $this->assertNotSame($xc->hex(), $yc->hex(), 'given (x != y): comp(x) != comp(y)');
        $one = $this->one();
        $this->assertSame($xc->add($x)->hex(), $one->hex(), 's + comp = 1 (mod L)');
        $this->assertSame($yc->add($y)->hex(), $one->hex(), 's + comp = 1 (mod L)');
    }

    public function one(): ScalarValue
    {
        return new ScalarValue(
            new HiddenString("\x01" . str_repeat("\x00", 31))
        );
    }

    public function zero(): ScalarValue
    {
        return new ScalarValue(
            new HiddenString(str_repeat("\x00", 32))
        );
    }

    /**
     * Based on the libsodium example
     *
     * @link https://libsodium.gitbook.io/doc/advanced/point-arithmetic/ristretto#example
     * @throws Exception
     * @throws SodiumException
     */
    public function testTwoPartyComputation(): void
    {
        $x = random_bytes(64);
        $px = GroupElement::fromHash($x);
        $r = ScalarValue::random();
        $gr = $r->multBase();
        $a = $px->add($gr);

        $k = ScalarValue::random();
        $v = $k->multBase();
        $b = $k->scalarPointMultiply($a);

        $ir = $r->negate();
        $vir = $v->scalarPointMultiply($ir);
        $fx = $b->add($vir);

        // If you knew px and k:
        $pxk = $px->scalarPointMultiply($k);

        $this->assertSame($fx->hex(), $pxk->hex(), 'Ristretto error');
    }

    public function testScalarPointMultiply()
    {
        $alice_sk1 = SecretKey::generate();
        $alice_sk2 = SecretKey::generate();
        $bob_sk1 = SecretKey::generate();
        $bob_sk2 = SecretKey::generate();

        $alice_pk1 = $alice_sk1->getPublicKey();
        $alice_pk2 = $alice_sk2->getPublicKey();
        $bob_pk1 = $bob_sk1->getPublicKey();
        $bob_pk2 = $bob_sk2->getPublicKey();

        $x0 = $alice_sk1->scalarPointMultiply($bob_pk1);
        $y0 = $bob_sk1->scalarPointMultiply($alice_pk1);
        $this->assertTrue($x0->equals($y0), 'scalar multiplication must be commutative');

        $x1 = $alice_sk2->scalarPointMultiply($bob_pk1);
        $y1 = $bob_sk1->scalarPointMultiply($alice_pk2);
        $this->assertTrue($x1->equals($y1), 'scalar multiplication must be commutative');

        $x2 = $alice_sk1->scalarPointMultiply($bob_pk2);
        $y2 = $bob_sk2->scalarPointMultiply($alice_pk1);
        $this->assertTrue($x2->equals($y2), 'scalar multiplication must be commutative');

        $x3 = $alice_sk2->scalarPointMultiply($bob_pk2);
        $y3 = $bob_sk2->scalarPointMultiply($alice_pk2);
        $this->assertTrue($x3->equals($y3), 'scalar multiplication must be commutative');

        $this->assertFalse($x0->equals($x1), 'must not arrive on same points');
        $this->assertFalse($x0->equals($x2), 'must not arrive on same points');
        $this->assertFalse($x0->equals($x3), 'must not arrive on same points');
        $this->assertFalse($x1->equals($x2), 'must not arrive on same points');
        $this->assertFalse($x1->equals($x3), 'must not arrive on same points');
        $this->assertFalse($x2->equals($x3), 'must not arrive on same points');

        $this->assertFalse($y0->equals($y1), 'must not arrive on same points');
        $this->assertFalse($y0->equals($y2), 'must not arrive on same points');
        $this->assertFalse($y0->equals($y3), 'must not arrive on same points');
        $this->assertFalse($y1->equals($y2), 'must not arrive on same points');
        $this->assertFalse($y1->equals($y3), 'must not arrive on same points');
        $this->assertFalse($y2->equals($y3), 'must not arrive on same points');
    }
}
