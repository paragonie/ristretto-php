<?php
declare(strict_types=1);
namespace ParagonIE\Ristretto;

use Exception;
use ParagonIE\HiddenString\HiddenString;
use SodiumException;

class SecretKey extends ScalarValue
{
    public function __construct(
        protected HiddenString $bytes,
        private ?PublicKey $pk = null
    ) {
        parent::__construct($bytes);
    }

    /**
     * @throws SodiumException
     * @throws Exception
     */
    public static function generate(): SecretKey
    {
        $sk = random_bytes(32);
        $c = unpack('C', $sk[31])[1] & 0x1f;
        $sk[31] = pack('C', $c);
        $pk = sodium_crypto_scalarmult_ristretto255_base($sk);
        return new SecretKey(
            new HiddenString($sk),
            new PublicKey(new HiddenString($pk))
        );
    }

    /**
     * @return PublicKey
     * @throws SodiumException
     */
    public function getPublicKey(): PublicKey
    {
        if (is_null($this->pk)) {
            $pk = sodium_crypto_scalarmult_ristretto255_base($this->bytes->getString());
            $this->pk = new PublicKey(new HiddenString($pk));
        }
        return $this->pk;
    }
}
