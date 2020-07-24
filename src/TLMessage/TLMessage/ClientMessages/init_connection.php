<?php

declare(strict_types=1);

namespace TelegramOSINT\TLMessage\TLMessage\ClientMessages;

use TelegramOSINT\LibConfig;
use TelegramOSINT\Registration\AccountInfo;
use TelegramOSINT\TLMessage\TLMessage\Packer;
use TelegramOSINT\TLMessage\TLMessage\TLClientMessage;

/**
 * @see https://core.telegram.org/method/initConnection
 */
class init_connection implements TLClientMessage
{
    private const CONSTRUCTOR = 3251461801; // 0xC1CD5EA9

    /**
     * @var AccountInfo
     */
    private $account;
    /**
     * @var TLClientMessage
     */
    private $query;
    /** @var json_object */
    private $params;
    /** @var null */
    private $proxy = null;
    /** @var int */
    private $flags;

    /**
     * @param AccountInfo          $authInfo
     * @param TLClientMessage|null $query
     * @param json_object|null     $params
     * @param int                  $flags
     */
    public function __construct(AccountInfo $authInfo, TLClientMessage $query = null, json_object $params = null, int $flags = 2048)
    {
        $this->account = $authInfo;
        $this->query = $query;
        $this->params = $params;
        $this->flags = $flags;
    }

    public function getName(): string
    {
        return 'init_connection';
    }

    public function toBinary(): string
    {
        $flags = $this->flags
            | ($this->params != null ? 0x2 : 0x0)
            | ($this->proxy != null ? 0x1 : 0x0);

        $paramData = ($this->params !== null ? Packer::packBytes($this->params->toBinary()) : '');

        return
            Packer::packConstructor(self::CONSTRUCTOR).
            Packer::packInt($flags).
            Packer::packInt(LibConfig::APP_API_ID).
            Packer::packString($this->account->getDevice()).
            Packer::packString($this->account->getAndroidSdkVersion()).
            Packer::packString($this->account->getAppVersion().' ('.$this->account->getAppVersionCode().')').
            Packer::packString($this->account->getDeviceLang()).
            Packer::packString(LibConfig::APP_DEFAULT_LANG_PACK).
            Packer::packString($this->account->getAppLang()). // lang_code
            // flags.0?InputClientProxy – skipped
            $paramData.
            ($this->query ? Packer::packBytes($this->query->toBinary()) : '');
    }

    private function getParams(): json_object
    {
        $data = new json_object_value(
            'data',
            new json_object_value_string(LibConfig::APP_CERT_SHA256)
        );
        $tz_offset = new json_object_value(
            'tz_offset',
            new json_object_value_number(LibConfig::APP_TZ_START)
        );

        return new json_object([
            $data,
            $tz_offset,
        ]);

    }
}
