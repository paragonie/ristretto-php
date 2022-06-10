<?php
declare(strict_types=1);
namespace ParagonIE\Ristretto;

use ParagonIE\ConstantTime\Hex;
use ParagonIE\HiddenString\HiddenString;

abstract class Ristretto
{
    public function __construct(protected HiddenString $bytes)
    {}

    public function equals(Ristretto $other): bool
    {
        return $this->bytes->equals($other->getBytes());
    }

    public function hex(): string
    {
        return Hex::encode($this->bytes->getString());
    }

    public function getBytes(): HiddenString
    {
        return $this->bytes;
    }
}
