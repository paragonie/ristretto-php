<?php
declare(strict_types=1);
namespace ParagonIE\Ristretto;

use ParagonIE\HiddenString\HiddenString;
use SodiumException;

class ScalarValue extends Ristretto
{
    /**
     * @throws SodiumException
     */
    public static function random(): ScalarValue
    {
        return new ScalarValue(
            new HiddenString(sodium_crypto_core_ristretto255_scalar_random())
        );
    }

    /**
     * @throws SodiumException
     */
    public function add(ScalarValue $other): ScalarValue
    {
        $result = sodium_crypto_core_ristretto255_scalar_add(
            $this->bytes->getString(),
            $other->getBytes()->getString()
        );
        return new ScalarValue(new HiddenString($result));
    }

    /**
     * @throws SodiumException
     */
    public function complement(): ScalarValue
    {
        return new ScalarValue(
            new HiddenString(
                sodium_crypto_core_ristretto255_scalar_complement($this->bytes->getString())
            )
        );
    }

    /**
     * @throws SodiumException
     */
    public function mul(ScalarValue $other): ScalarValue
    {
        $result = sodium_crypto_core_ristretto255_scalar_mul(
            $this->bytes->getString(),
            $other->getBytes()->getString()
        );
        return new ScalarValue(new HiddenString($result));
    }

    /**
     * @throws SodiumException
     */
    public function sub(ScalarValue $other): ScalarValue
    {
        $result = sodium_crypto_core_ristretto255_scalar_sub(
            $this->bytes->getString(),
            $other->getBytes()->getString()
        );
        return new ScalarValue(new HiddenString($result));
    }

    /**
     * @throws SodiumException
     */
    public function multBase(): GroupElement
    {
        return new GroupElement(
            new HiddenString(
                sodium_crypto_scalarmult_ristretto255_base($this->bytes->getString())
            )
        );
    }

    /**
     * @throws SodiumException
     */
    public function invert(): ScalarValue
    {
        return new ScalarValue(
            new HiddenString(
                sodium_crypto_core_ristretto255_scalar_invert($this->bytes->getString())
            )
        );
    }

    /**
     * @throws SodiumException
     */
    public function negate(): ScalarValue
    {
        return new ScalarValue(
            new HiddenString(
                sodium_crypto_core_ristretto255_scalar_negate($this->bytes->getString())
            )
        );
    }

    /**
     * @throws SodiumException
     */
    public function scalarPointMultiply(GroupElement $pk): GroupElement
    {
        return new GroupElement(
            new HiddenString(
                sodium_crypto_scalarmult_ristretto255(
                    $this->bytes->getString(),
                    $pk->getBytes()->getString()
                )
            )
        );
    }
}
