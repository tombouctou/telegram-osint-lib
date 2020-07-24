<?php

declare(strict_types=1);

namespace TelegramOSINT\Registration;

use TelegramOSINT\Auth\Protocol\AppAuthorization;
use TelegramOSINT\Auth\Protocol\BaseAuthorization;
use TelegramOSINT\Client\AuthKey\AuthInfo;
use TelegramOSINT\Client\AuthKey\AuthKey;
use TelegramOSINT\Client\AuthKey\AuthKeyCreator;
use TelegramOSINT\Exception\TGException;
use TelegramOSINT\LibConfig;
use TelegramOSINT\Logger\ClientDebugLogger;
use TelegramOSINT\Logger\Logger;
use TelegramOSINT\MTSerialization\AnonymousMessage;
use TelegramOSINT\TGConnection\DataCentre;
use TelegramOSINT\TGConnection\Socket\NonBlockingProxySocket;
use TelegramOSINT\TGConnection\Socket\TcpSocket;
use TelegramOSINT\TGConnection\SocketMessenger\EncryptedSocketMessenger;
use TelegramOSINT\TGConnection\SocketMessenger\MessageListener;
use TelegramOSINT\TGConnection\SocketMessenger\SocketMessenger;
use TelegramOSINT\TLMessage\TLMessage\ClientMessages\get_blocked_contacts;
use TelegramOSINT\TLMessage\TLMessage\ClientMessages\get_config;
use TelegramOSINT\TLMessage\TLMessage\ClientMessages\get_contacts;
use TelegramOSINT\TLMessage\TLMessage\ClientMessages\get_dialogs;
use TelegramOSINT\TLMessage\TLMessage\ClientMessages\get_faved_stickers;
use TelegramOSINT\TLMessage\TLMessage\ClientMessages\get_featured_stickers;
use TelegramOSINT\TLMessage\TLMessage\ClientMessages\get_invite_text;
use TelegramOSINT\TLMessage\TLMessage\ClientMessages\get_langpack;
use TelegramOSINT\TLMessage\TLMessage\ClientMessages\get_languages;
use TelegramOSINT\TLMessage\TLMessage\ClientMessages\get_notify_settings;
use TelegramOSINT\TLMessage\TLMessage\ClientMessages\get_pinned_dialogs;
use TelegramOSINT\TLMessage\TLMessage\ClientMessages\get_state;
use TelegramOSINT\TLMessage\TLMessage\ClientMessages\get_statuses;
use TelegramOSINT\TLMessage\TLMessage\ClientMessages\get_terms_of_service_update;
use TelegramOSINT\TLMessage\TLMessage\ClientMessages\get_top_peers;
use TelegramOSINT\TLMessage\TLMessage\ClientMessages\init_connection;
use TelegramOSINT\TLMessage\TLMessage\ClientMessages\input_notify_chats;
use TelegramOSINT\TLMessage\TLMessage\ClientMessages\input_notify_users;
use TelegramOSINT\TLMessage\TLMessage\ClientMessages\invoke_with_layer;
use TelegramOSINT\TLMessage\TLMessage\ClientMessages\json_object;
use TelegramOSINT\TLMessage\TLMessage\ClientMessages\json_object_value;
use TelegramOSINT\TLMessage\TLMessage\ClientMessages\json_object_value_string;
use TelegramOSINT\TLMessage\TLMessage\ClientMessages\send_sms_code;
use TelegramOSINT\TLMessage\TLMessage\ClientMessages\sign_in;
use TelegramOSINT\TLMessage\TLMessage\ClientMessages\sign_up;
use TelegramOSINT\TLMessage\TLMessage\ClientMessages\update_status;
use TelegramOSINT\TLMessage\TLMessage\ServerMessages\AuthorizationContactUser;
use TelegramOSINT\TLMessage\TLMessage\ServerMessages\DcConfigApp;
use TelegramOSINT\TLMessage\TLMessage\ServerMessages\Languages;
use TelegramOSINT\TLMessage\TLMessage\ServerMessages\SentCodeApp;
use TelegramOSINT\Tools\Phone;
use TelegramOSINT\Tools\Proxy;

class RegistrationFromTgApp implements RegisterInterface, MessageListener
{
    /**
     * @var AuthKey
     */
    private $blankAuthKey;
    /**
     * @var SocketMessenger
     */
    private $socketMessenger;
    /**
     * @var AccountInfo
     */
    private $accountInfo;
    /**
     * @var Proxy
     */
    private $proxy;
    /**
     * @var string
     */
    private $phone;
    /**
     * @var string
     */
    private $phoneHash;
    /**
     * @var bool
     */
    private $isSmsRequested = false;
    /** @var Logger */
    private $logger;
    /** @var DataCentre */
    private $dataCentre;
    /** @var BaseAuthorization|null */
    private $baseAuth;

    /**
     * @param Proxy|null             $proxy
     * @param AccountInfo|null       $accountInfo
     * @param ClientDebugLogger|null $logger
     * @param DataCentre|null        $dataCentre
     */
    public function __construct(
        Proxy $proxy = null,
        AccountInfo $accountInfo = null,
        ClientDebugLogger $logger = null,
        ?DataCentre $dataCentre = null
    ) {
        $this->accountInfo = $accountInfo ?: AccountInfo::generate();
        $this->proxy = $proxy;
        $this->logger = $logger;
        $this->dataCentre = $dataCentre ?? DataCentre::getDefault();
    }

    /**
     * @param string   $phoneNumber
     * @param callable $cb          function()
     * @param bool     $allowReReg
     *
     * @throws TGException
     */
    public function requestCodeForPhone(string $phoneNumber, callable $cb, bool $allowReReg = false): void
    {
        $phoneNumber = trim($phoneNumber);

        $this->phone = $phoneNumber;
        $this->requestBlankAuthKey(function (AuthKey $authKey, string $sessionId) use ($phoneNumber, $cb, $allowReReg) {
            $this->blankAuthKey = $authKey;
            $this->baseAuth = null;

            $this->initSocketMessenger($this->dataCentre, $sessionId, function () use ($phoneNumber, $cb, $allowReReg) {
                $this->initSocketAsOfficialApp(function () use ($phoneNumber, $cb, $allowReReg) {
                    $request = new send_sms_code($phoneNumber);
                    $this->socketMessenger->getResponseAsync($request, function (AnonymousMessage $smsSentResponse) use ($cb, $allowReReg) {
                        $smsSentResponseObj = new SentCodeApp($smsSentResponse);

                        $isReReg = $allowReReg && ($smsSentResponseObj->isSentCodeTypeApp() || $smsSentResponseObj->isSentCodeTypeSms());
                        if (!$isReReg && !$smsSentResponseObj->isSentCodeTypeSms()) {
                            throw new TGException(TGException::ERR_REG_USER_ALREADY_EXISTS, $smsSentResponse);
                        }
                        $this->phoneHash = $smsSentResponseObj->getPhoneCodeHash();
                        $this->isSmsRequested = true;
                        $cb($isReReg);
                    });
                });
            });
        });
    }

    /**
     * pre-actions
     *
     * @param callable $onLastMessageReceived function(AnonymousMessage $message)
     */
    private function initSocketAsOfficialApp(callable $onLastMessageReceived): void
    {
        // config
        $getConfig = new get_config();
        // @see https://github.com/DrKLO/Telegram/blob/master/TMessagesProj/jni/tgnet/MTProtoScheme.cpp#L1103
        //$hash = hash('sha256', rand(1, 10000).'sadgsdgerhew54635634s');
        $hash = '49C1522548EBACD46CE322B6FD47F6092BB745D0F88082145CAF35E14DCC38E1';
        $params = new json_object([
            new json_object_value('device_token', new json_object_value_string('__FIREBASE_GENERATING_SINCE_'.time().'__')),
            // sha256
            new json_object_value('data', new json_object_value_string(strtoupper($hash))),
        ]);
        $initConnection = new init_connection($this->accountInfo, $getConfig, $params, 1024);
        $invokeWithLayer = new invoke_with_layer(LibConfig::APP_DEFAULT_TL_LAYER_VERSION, $initConnection);

        $this->socketMessenger->getResponseAsync($invokeWithLayer, function (AnonymousMessage $configResponse) use ($onLastMessageReceived) {
            new DcConfigApp($configResponse);

            // possible languages
            $getLanguages = new get_languages();
            $this->socketMessenger->getResponseAsync($getLanguages, function (AnonymousMessage $languages) use ($onLastMessageReceived) {
                $languagesResponse = new Languages($languages);

                if($languagesResponse->getCount() < 5) {
                    throw new TGException(TGException::ERR_REG_NOT_OFFICIAL_USER);
                }
                // get language strings
                $getLangPack = new get_langpack($this->accountInfo->getAppLang());
                $this->socketMessenger->getResponseAsync($getLangPack, $onLastMessageReceived);
            });
        });
    }

    /**
     * @param DataCentre $dc
     * @param callable   $cb
     *
     * @throws TGException
     */
    private function initSocketMessenger(DataCentre $dc, string $sessionId, callable $cb): void
    {
        $socket = $this->proxy instanceof Proxy
            ? new NonBlockingProxySocket($this->proxy, $dc, $cb)
            : new TcpSocket($dc, $cb);

        $this->socketMessenger = new EncryptedSocketMessenger($socket, $this->blankAuthKey, $this, $this->logger, $sessionId);
    }

    /**
     * @param callable $cb function(AuthKey $authKey)
     *
     * @throws TGException
     */
    private function requestBlankAuthKey(callable $cb): void
    {
        (new AppAuthorization($this->dataCentre))->createAuthKey($cb, true);
    }

    /**
     * @param string   $smsCode
     * @param callable $onAuthKeyReady function(AuthKey $authKey)
     * @param bool     $reReg
     *
     * @throws TGException
     */
    public function confirmPhoneWithSmsCode(string $smsCode, callable $onAuthKeyReady, bool $reReg = false): void
    {
        $smsCode = trim($smsCode);

        if(!$this->isSmsRequested) {
            throw new TGException(TGException::ERR_REG_REQUEST_SMS_CODE_FIRST);
        }
        $this->signInFailed($smsCode, function () use ($onAuthKeyReady, $reReg) {
            sleep(5);
            if (!$reReg) {
                $this->signUp(function () use ($onAuthKeyReady) {
                    $this->performLoginWorkFlow(function () use ($onAuthKeyReady) {
                        $this->socketMessenger->terminate();

                        $authInfo = (new AuthInfo())
                            ->setPhone($this->phone)
                            ->setAccountInfo($this->accountInfo);

                        $onAuthKeyReady(AuthKeyCreator::attachAuthInfo($this->blankAuthKey, $authInfo));
                    });
                });
            } else {
                $this->socketMessenger->terminate();
                $authInfo = (new AuthInfo())
                    ->setPhone($this->phone)
                    ->setAccountInfo($this->accountInfo);

                $onAuthKeyReady(AuthKeyCreator::attachAuthInfo($this->blankAuthKey, $authInfo));
            }
        });
    }

    /**
     * post-actions
     *
     * @param callable $cb function(AnonymousMessage $message)
     */
    private function performLoginWorkFlow(callable $cb): void
    {
        $this->socketMessenger->getResponseConsecutive([
            new get_config(),
            new update_status(true),
            new get_terms_of_service_update(),
            new get_notify_settings(new input_notify_chats()),
            new get_notify_settings(new input_notify_users()),
            new get_invite_text(),
            new get_pinned_dialogs(),
            new get_state(),
            new get_blocked_contacts(),
            new get_contacts(),
            new get_dialogs(),
            new get_faved_stickers(),
            new get_featured_stickers(),
            new get_top_peers(),
            new get_statuses(),
        ], $cb);
    }

    /**
     * @param string   $smsCode
     * @param callable $onMessageReceived function(AnonymousMessage $message)
     */
    private function signInFailed(string $smsCode, callable $onMessageReceived): void
    {
        $signInMessage = new sign_in(
            $this->phone,
            $this->phoneHash,
            trim($smsCode)
        );

        $this->socketMessenger->getResponseAsync($signInMessage, $onMessageReceived);
        //return
        //    RpcError::isIt($response) &&
        //    (new RpcError($response))->isPhoneNumberUnoccupied();
    }

    /**
     * @param callable $onUserAuthorized function(AuthorizationContactUser $user)
     */
    private function signUp(callable $onUserAuthorized): void
    {
        $signUpMessage = new sign_up(
            $this->phone,
            $this->phoneHash,
            $this->accountInfo->getFirstName(),
            $this->accountInfo->getLastName()
        );

        $this->socketMessenger->getResponseAsync($signUpMessage, function (AnonymousMessage $response) use ($onUserAuthorized) {
            $authResponse = new AuthorizationContactUser($response);
            $this->checkSigningResponse($authResponse);
            $onUserAuthorized($authResponse);
        });
    }

    /**
     * @param AuthorizationContactUser $response
     *
     * @throws TGException
     */
    private function checkSigningResponse(AuthorizationContactUser $response): void
    {
        if(!Phone::equal($response->getUser()->getPhone(), $this->phone)) {
            throw new TGException(TGException::ERR_REG_FAILED);
        }
    }

    /**
     * @param AnonymousMessage $message
     */
    public function onMessage(AnonymousMessage $message): void
    {
    }

    /**
     * @throws TGException
     */
    public function pollMessages(): void
    {
        while(true) {
            if ($this->socketMessenger) {
                /** @noinspection UnusedFunctionResultInspection */
                $this->socketMessenger->readMessage();
            }
            if ($this->baseAuth) {
                $this->baseAuth->poll();
            }
        }
    }

    public function terminate(): void
    {
        $this->socketMessenger->terminate();
    }
}
