<?php

namespace TelegramOSINT\Registration;

use JsonException;
use TelegramOSINT\Exception\TGException;
use TelegramOSINT\LibConfig;
use TelegramOSINT\Registration\DeviceGenerator\DeviceResource;
use TelegramOSINT\Registration\NameGenerator\NameResource;

class AccountInfo
{
    /** @var string */
    private $device;
    /** @var string */
    private $androidSdkVersion;

    /** @var string */
    private $firstName;
    /** @var string */
    private $lastName;

    /** @var string */
    private $deviceLang;
    /** @var string */
    private $appLang;

    /** @var string */
    private $appVersion;
    /** @var string */
    private $appVersionCode;
    /** @var int */
    private $layerVersion;

    private function __construct()
    {
    }

    /**
     * @return AccountInfo
     */
    public static function generate(): self
    {
        $acc = new self();

        $device = new DeviceResource();
        $acc->device = $device->getDeviceString();
        $acc->androidSdkVersion = $device->getSdkString();
        unset($device);

        $human = new NameResource();
        $acc->firstName = $human->getName();
        $acc->lastName = $human->getLastName();
        unset($humanName);

        $acc->deviceLang = LibConfig::APP_DEFAULT_DEVICE_LANG_CODE;
        $acc->appLang = LibConfig::APP_DEFAULT_LANG_CODE;
        $acc->appVersion = LibConfig::APP_DEFAULT_VERSION;
        $acc->appVersionCode = LibConfig::APP_DEFAULT_VERSION_CODE;
        $acc->layerVersion = LibConfig::APP_DEFAULT_TL_LAYER_VERSION;

        return $acc;
    }

    /**
     * @return string
     */
    public function serializeToJson(): string
    {
        $bundle = [];
        $bundle['device'] = $this->device;
        $bundle['androidSdkVersion'] = $this->androidSdkVersion;
        $bundle['firstName'] = $this->firstName;
        $bundle['lastName'] = $this->lastName;
        $bundle['deviceLang'] = $this->deviceLang;
        $bundle['appLang'] = $this->appLang;
        $bundle['appVersion'] = $this->appVersion;
        $bundle['appVersionCode'] = $this->appVersionCode;
        $bundle['layerVersion'] = $this->layerVersion;

        try {
            return json_encode($bundle, JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            return '{}';
        }
    }

    /**
     * @param string $serialized
     *
     * @throws TGException
     *
     * @return AccountInfo
     */
    public static function deserializeFromJson(string $serialized): self
    {
        try {
            $bundle = json_decode($serialized, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new TGException(TGException::ERR_AUTH_KEY_BAD_ACCOUNT_INFO);
        }

        if(!$bundle) {
            throw new TGException(TGException::ERR_AUTH_KEY_BAD_ACCOUNT_INFO);
        }
        $accountInfo = new self();
        $accountInfo->device = $bundle['device'];
        $accountInfo->androidSdkVersion = $bundle['androidSdkVersion'];
        $accountInfo->firstName = $bundle['firstName'];
        $accountInfo->lastName = $bundle['lastName'];
        $accountInfo->deviceLang = $bundle['deviceLang'];
        $accountInfo->appLang = $bundle['appLang'];
        $accountInfo->appVersion = $bundle['appVersion'];
        $accountInfo->appVersionCode = $bundle['appVersionCode'];
        $accountInfo->layerVersion = $bundle['layerVersion'];

        return $accountInfo;
    }

    public function getDevice(): string
    {
        return $this->device;
    }

    public function getAndroidSdkVersion(): string
    {
        return $this->androidSdkVersion;
    }

    public function getFirstName(): string
    {
        return $this->firstName;
    }

    public function getLastName(): string
    {
        return $this->lastName;
    }

    public function getDeviceLang(): string
    {
        return $this->deviceLang;
    }

    public function getAppLang(): string
    {
        return $this->appLang;
    }

    public function getAppVersion(): string
    {
        return $this->appVersion;
    }

    public function getAppVersionCode(): string
    {
        return $this->appVersionCode;
    }

    public function getLayerVersion(): int
    {
        return $this->layerVersion;
    }

    public function setDeviceModel(string $deviceModel): void
    {
        $this->device = $deviceModel;
    }

    public function setSdkVersion(string $version): void
    {
        $this->androidSdkVersion = $version;
    }

    public function setFirstName(string $firstName): void
    {
        $this->firstName = $firstName;
    }

    public function setLastName(string $lastName): void
    {
        $this->lastName = $lastName;
    }
}
