<?php

declare(strict_types=1);

namespace TelegramOSINT\TLMessage\TLMessage\ClientMessages;

use TelegramOSINT\TLMessage\TLMessage\Packer;
use TelegramOSINT\TLMessage\TLMessage\TLClientMessage;

/**
 * @see https://core.telegram.org/method/auth.bindTempAuthKey
 */
class bind_auth_key_inner implements TLClientMessage
{
    private const CONSTRUCTOR = 0x75a3f765;

    /** @var string */
    private $nonce;
    /** @var string */
    private $perm_auth_key_id;
    /** @var string */
    private $temp_auth_key_id;
    /** @var string */
    private $temp_session_id;
    /** @var int */
    private $expires_at;

    /**
     * bind_auth_key_inner constructor.
     *
     * @param string $nonce            'long' by protocol
     * @param string $perm_auth_key_id 'long' by protocol
     * @param string $temp_auth_key_id 'long' by protocol
     * @param string $temp_session_id  'long' by protocol
     * @param int    $expires_at
     */
    public function __construct(string $nonce, string $perm_auth_key_id, string $temp_auth_key_id, string $temp_session_id, int $expires_at)
    {
        $this->nonce = $nonce;
        $this->perm_auth_key_id = $perm_auth_key_id;
        $this->temp_auth_key_id = $temp_auth_key_id;
        $this->temp_session_id = $temp_session_id;
        $this->expires_at = $expires_at;
    }

    public function getName(): string
    {
        return 'bind_auth_key_inner';
    }

    public function toBinary(): string
    {
        return Packer::packConstructor(self::CONSTRUCTOR).
            Packer::packBytes($this->nonce).
            Packer::packBytes($this->temp_auth_key_id).
            Packer::packBytes($this->perm_auth_key_id).
            Packer::packBytes($this->temp_session_id).
            Packer::packInt($this->expires_at);
    }
}
