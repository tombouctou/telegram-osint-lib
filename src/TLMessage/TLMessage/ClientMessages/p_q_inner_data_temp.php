<?php

/** @noinspection DuplicatedCode */
declare(strict_types=1);

namespace TelegramOSINT\TLMessage\TLMessage\ClientMessages;

use TelegramOSINT\TLMessage\TLMessage\Packer;
use TelegramOSINT\TLMessage\TLMessage\TLClientMessage;

/**
 * @see https://core.telegram.org/mtproto/auth_key
 */
class p_q_inner_data_temp implements TLClientMessage
{
    private const CONSTRUCTOR = 0x3c6a84d4;

    /**
     * @var int
     */
    private $pq;
    /**
     * @var int
     */
    private $p;
    /**
     * @var int
     */
    private $q;
    /**
     * @var string
     */
    private $oldClientNonce;
    /**
     * @var string
     */
    private $serverNonce;
    /**
     * @var string
     */
    private $newClientNonce;
    /**
     * @var int
     */
    private $expiresIn;

    /**
     * p_q_inner_data constructor.
     *
     * @param int    $pq
     * @param int    $p
     * @param int    $q
     * @param string $oldClientNonce
     * @param string $serverNonce
     * @param string $newClientNonce
     * @param int    $expiresIn
     */
    public function __construct(int $pq, int $p, int $q, string $oldClientNonce, string $serverNonce, string $newClientNonce, int $expiresIn)
    {
        $this->pq = $pq;
        $this->p = $p;
        $this->q = $q;
        $this->oldClientNonce = $oldClientNonce;
        $this->serverNonce = $serverNonce;
        $this->newClientNonce = $newClientNonce;

        assert($this->p < $this->q);
        assert($this->p * $this->q == $this->pq);
        $this->expiresIn = $expiresIn;

    }

    public function getName(): string
    {
        return 'pq_inner_data_temp';
    }

    public function toBinary(): string
    {
        return
            Packer::packConstructor(self::CONSTRUCTOR).
            Packer::packLongAsBytes($this->pq).
            Packer::packIntAsBytesLittleEndian($this->p).
            Packer::packIntAsBytesLittleEndian($this->q).
            Packer::packBytes($this->oldClientNonce).
            Packer::packBytes($this->serverNonce).
            Packer::packBytes($this->newClientNonce).
            Packer::packInt($this->expiresIn);
    }
}
