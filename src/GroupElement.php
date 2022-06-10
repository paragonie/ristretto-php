<?php
declare(strict_types=1);
namespace ParagonIE\Ristretto;

use ParagonIE\HiddenString\HiddenString;
use SodiumException;

class GroupElement extends Ristretto
{
    /**
     * @throws SodiumException
     */
    public function add(GroupElement $element): GroupElement
    {
        $result = sodium_crypto_core_ristretto255_add(
            $this->bytes->getString(),
            $element->getBytes()->getString()
        );
        return new GroupElement(new HiddenString($result));
    }

    /**
     * @throws SodiumException
     */
    public static function random(): GroupElement
    {
        return new GroupElement(
            new HiddenString(sodium_crypto_core_ristretto255_random())
        );
    }

    /**
     * @throws SodiumException
     */
    public static function fromHash(string $hash): GroupElement
    {
        return new GroupElement(
            new HiddenString(sodium_crypto_core_ristretto255_from_hash($hash))
        );
    }

    /**
     * @throws SodiumException
     */
    public function sub(GroupElement $element): GroupElement
    {
        $result = sodium_crypto_core_ristretto255_sub(
            $this->bytes->getString(),
            $element->getBytes()->getString()
        );
        return new GroupElement(new HiddenString($result));
    }

    /**
     * @throws SodiumException
     */
    public function scalarPointMultiply(ScalarValue $s): GroupElement
    {
        return new GroupElement(
            new HiddenString(
                sodium_crypto_scalarmult_ristretto255(
                    $s->getBytes()->getString(),
                    $this->bytes->getString()
                )
            )
        );
    }
}
