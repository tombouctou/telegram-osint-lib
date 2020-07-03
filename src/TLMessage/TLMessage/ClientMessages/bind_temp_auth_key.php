<?php

declare(strict_types=1);

namespace TelegramOSINT\TLMessage\TLMessage\ClientMessages;

use TelegramOSINT\TLMessage\TLMessage\Packer;
use TelegramOSINT\TLMessage\TLMessage\TLClientMessage;

/**
 * @see https://core.telegram.org/method/auth.bindTempAuthKey
 */
class bind_temp_auth_key implements TLClientMessage
{
    private const CONSTRUCTOR = 0xcdd42a05;

    /** @var string */
    private $perm_auth_key_id;
    /** @var string */
    private $nonce;
    /** @var int */
    private $expires_at;
    /** @var string */
    private $encrypted_message;

    public function __construct(string $perm_auth_key_id, string $nonce, int $expires_at, string $encrypted_message)
    {
        $this->perm_auth_key_id = $perm_auth_key_id;
        $this->nonce = $nonce;
        $this->expires_at = $expires_at;
        $this->encrypted_message = $encrypted_message;
    }

    public function getName(): string
    {
        return 'bind_temp_auth_key';
    }

    public function toBinary(): string
    {
        return Packer::packConstructor(self::CONSTRUCTOR).
            Packer::packBytes($this->perm_auth_key_id). // long
            Packer::packBytes($this->nonce). // long
            Packer::packInt($this->expires_at).
            Packer::packString($this->encrypted_message);
    }
}
