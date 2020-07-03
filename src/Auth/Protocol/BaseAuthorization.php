<?php

namespace TelegramOSINT\Auth\Protocol;

use function sha1;
use function substr;
use TelegramOSINT\Auth\AES\AES;
use TelegramOSINT\Auth\AES\PhpSecLibAES;
use TelegramOSINT\Auth\Authorization;
use TelegramOSINT\Auth\AuthParams;
use TelegramOSINT\Auth\Certificate\Certificate;
use TelegramOSINT\Auth\Factorization\GmpFactorizer;
use TelegramOSINT\Auth\Factorization\PQ;
use TelegramOSINT\Auth\PowMod\PhpSecLibPowMod;
use TelegramOSINT\Auth\PowMod\PowMod;
use TelegramOSINT\Auth\RSA\PhpSecLibRSA;
use TelegramOSINT\Auth\RSA\RSA;
use TelegramOSINT\Client\AuthKey\AuthKeyCreator;
use TelegramOSINT\Exception\TGException;
use TelegramOSINT\Logger\Logger;
use TelegramOSINT\MTSerialization\AnonymousMessage;
use TelegramOSINT\MTSerialization\OwnImplementation\OwnDeserializer;
use TelegramOSINT\TGConnection\DataCentre;
use TelegramOSINT\TGConnection\Socket\NonBlockingProxySocket;
use TelegramOSINT\TGConnection\Socket\TcpSocket;
use TelegramOSINT\TGConnection\SocketMessenger\NotEncryptedSocketMessenger;
use TelegramOSINT\TLMessage\TLMessage\ClientMessages\bind_auth_key_inner;
use TelegramOSINT\TLMessage\TLMessage\ClientMessages\bind_temp_auth_key;
use TelegramOSINT\TLMessage\TLMessage\ClientMessages\client_dh_inner_data;
use TelegramOSINT\TLMessage\TLMessage\ClientMessages\req_dh_params;
use TelegramOSINT\TLMessage\TLMessage\ClientMessages\req_pq_multi;
use TelegramOSINT\TLMessage\TLMessage\ClientMessages\set_client_dh_params;
use TelegramOSINT\TLMessage\TLMessage\Packer;
use TelegramOSINT\TLMessage\TLMessage\ServerMessages\Auth\DHGenOk;
use TelegramOSINT\TLMessage\TLMessage\ServerMessages\Auth\DHReq;
use TelegramOSINT\TLMessage\TLMessage\ServerMessages\Auth\DHServerInnerData;
use TelegramOSINT\TLMessage\TLMessage\ServerMessages\Auth\ResPQ;
use TelegramOSINT\TLMessage\TLMessage\TLClientMessage;
use TelegramOSINT\Tools\Proxy;

abstract class BaseAuthorization implements Authorization
{
    private const LONG_BYTES = 8;

    /**
     * @var DataCentre
     */
    private $dc;
    /**
     * @var NotEncryptedSocketMessenger
     */
    private $socketContainer;
    /**
     * @var string
     */
    private $oldClientNonce;
    /**
     * @var string
     */
    private $newClientNonce;
    /**
     * @var string
     */
    private $obtainedServerNonce;
    /**
     * @var RSA
     */
    private $rsa;
    /**
     * @var AES
     */
    private $aes;
    /**
     * @var PowMod
     */
    private $powMod;
    /**
     * @var string
     */
    private $tmpAesKey;
    /**
     * @var string
     */
    private $tmpAesIV;
    /** @var string */
    private $sessionId;

    /**
     * @param DataCentre $dc    DC AuthKey must be generated on
     * @param Proxy|null $proxy
     *
     * @throws TGException
     */
    public function __construct(DataCentre $dc, ?Proxy $proxy = null)
    {
        $cb = static function () {
        };
        $socket = $proxy
            ? new NonBlockingProxySocket($proxy, $dc, $cb)
            : new TcpSocket($dc, $cb);

        $this->dc = $dc;
        $this->socketContainer = new NotEncryptedSocketMessenger($socket);

        $this->rsa = new PhpSecLibRSA();
        $this->aes = new PhpSecLibAES();
        $this->powMod = new PhpSecLibPowMod();

        /** @noinspection CryptographicallySecureRandomnessInspection */
        $this->oldClientNonce = openssl_random_pseudo_bytes(16, $strong);
        if ($strong === false || $this->oldClientNonce === false) {
            throw new TGException(TGException::ERR_CRYPTO_INVALID);
        }
        /** @noinspection CryptographicallySecureRandomnessInspection */
        $this->newClientNonce = openssl_random_pseudo_bytes(32, $strong);
        if ($strong === false || $this->newClientNonce === false) {
            throw new TGException(TGException::ERR_CRYPTO_INVALID);
        }
    }

    /**
     * @param int    $pq
     * @param int    $p
     * @param int    $q
     * @param string $oldClientNonce
     * @param string $serverNonce
     * @param string $newClientNonce
     * @param bool   $isTemp
     *
     * @return TLClientMessage
     */
    abstract protected function getPqInnerDataMessage($pq, $p, $q, $oldClientNonce, $serverNonce, $newClientNonce, bool $isTemp = false);

    /**
     * @param callable $onAuthKeyReady function(AuthKey $authKey)
     * @param bool     $forRegister
     *
     * @throws TGException
     */
    public function createAuthKey(callable $onAuthKeyReady, bool $forRegister = false)
    {
        $this->requestForPQ(function (ResPQ $pqResponse) use ($onAuthKeyReady, $forRegister) {
            $primes = $this->findPrimes($pqResponse->getPq());
            $this->requestDHParams($primes, $pqResponse, function ($dhResponse) use ($onAuthKeyReady, $pqResponse, $forRegister) {
                $dhParams = $this->decryptDHResponse($dhResponse, $pqResponse);
                $this->setClientDHParams(
                    $dhParams,
                    $pqResponse,
                    function (AuthParams $authKeyParams) use ($onAuthKeyReady, $forRegister) {
                        if ($forRegister) {
                            $this->bindTempAuthKey($authKeyParams, $onAuthKeyReady);
                        } else {
                            $onAuthKeyReady(AuthKeyCreator::createActual(
                                $authKeyParams->getAuthKey(),
                                $authKeyParams->getServerSalt(),
                                $this->dc
                            ), $this->sessionId);
                        }
                    }
                );
            });
        });
    }

    /**
     * @param AuthParams $permAuthParams permanent auth key params
     * @param callable   $onAuthKeyReady
     *
     * @throws TGException
     */
    protected function bindTempAuthKey(AuthParams $permAuthParams, callable $onAuthKeyReady): void
    {
        $this->requestForPQ(function (ResPQ $pqResponse) use ($onAuthKeyReady, $permAuthParams) {
            $primes = $this->findPrimes($pqResponse->getPq());
            $this->requestDHParams($primes, $pqResponse, function ($dhResponse) use ($onAuthKeyReady, $pqResponse, $permAuthParams) {
                $dhParams = $this->decryptDHResponse($dhResponse, $pqResponse);
                $this->setClientDHParams(
                    $dhParams,
                    $pqResponse,
                    function (AuthParams $authKeyParams) use ($onAuthKeyReady, $permAuthParams) {
                        $nonce = openssl_random_pseudo_bytes(self::LONG_BYTES);
                        $this->sessionId = openssl_random_pseudo_bytes(self::LONG_BYTES);
                        $permAuthKeyId = $permAuthParams->getAuthKeyId();
                        $tmpAuthKeyId = $authKeyParams->getAuthKeyId();
                        $expiresAt = time() + 60000;
                        $bindKey = new bind_auth_key_inner(
                            $nonce,
                            $permAuthKeyId,
                            $tmpAuthKeyId,
                            $this->sessionId,
                            $expiresAt
                        );
                        $messageId = $this->socketContainer->getMessageId();
                        $encryptedMessage = $this->encryptMessage($bindKey->toBinary(), $messageId, $permAuthParams);
                        $request = new bind_temp_auth_key(
                            $permAuthKeyId,
                            $nonce,
                            $expiresAt,
                            $encryptedMessage
                        );
                        $this->socketContainer->getResponseAsync($request, function (AnonymousMessage $response) use ($onAuthKeyReady, $authKeyParams) {
                            echo "GOT RESPONSE from bind_temp_auth_key\n";
                            // should be true
                            echo $response->getDebugPrintable();
                            $authKeyTemp = AuthKeyCreator::createActual(
                                $authKeyParams->getAuthKey(),
                                $authKeyParams->getServerSalt(),
                                $this->dc
                            );
                            $onAuthKeyReady($authKeyTemp, $this->sessionId);
                            die();
                        });
                    }
                );
            }, true);
        });
    }

    /**
     * This binding message is encrypted in the usual way, but with MTProto v1 using the perm_auth_key.
     * In other words, one has to prepend random:int128 (it replaces the customary session_id:long and salt:long that are irrelevant in this case),
     * then append the same msg_id that will be used for the request, a seqno equal to zero,
     * and the correct msg_len (40 bytes in this case); after that, one computes the msg_key:int128 as SHA1 of the resulting string,
     * appends padding necessary for a 16-byte alignment, encrypts the resulting string using the key derived from perm_auth_key and msg_key,
     * and prepends perm_auth_key_id and msg_key to the encrypted data as usual.
     *
     * @see https://core.telegram.org/mtproto_v1
     *
     * @param string     $binaryMessage
     * @param int        $messageId
     * @param AuthParams $authParams
     *
     * @throws TGException
     *
     * @return string
     */
    private function encryptMessage(string $binaryMessage, int $messageId, AuthParams $authParams): string
    {
        $seq_no = 0;
        $randomPrefix = openssl_random_pseudo_bytes(16);

        $length = strlen($binaryMessage);
        if ($length !== 40) {
            throw new TGException(TGException::ERR_ASSERT_BIND_KEY_LENGTH_VALID);
        }

        $data = $randomPrefix.
            Packer::packLong($messageId).
            pack('VV', $seq_no, $length).
            $binaryMessage;
        $msgKeyLarge = sha1($data, true);
        // 128-bit
        $msgKey = substr($msgKeyLarge, -16);

        $padding = $this->calcRemainder(-$length, 16);
        $padding = openssl_random_pseudo_bytes($padding);

        $payload = $data.$padding;

        list($aes_key, $aes_iv) = self::oldAesCalculate($msgKey, $authParams->getAuthKey());
        $encryptedPayload = $this->aes->encryptIgeMode($payload, $aes_key, $aes_iv);

        return
            $authParams->getAuthKeyId().
            $msgKey.
            $encryptedPayload;
    }

    /** @noinspection DuplicatedCode */
    private static function oldAesCalculate(string $msg_key, string $auth_key, bool $to_server = true): array
    {
        $x = $to_server ? 0 : 8;
        $sha1_a = sha1($msg_key.substr($auth_key, $x, 32), true);
        $sha1_b = sha1(substr($auth_key, 32 + $x, 16).$msg_key.substr($auth_key, 48 + $x, 16), true);
        $sha1_c = sha1(substr($auth_key, 64 + $x, 32).$msg_key, true);
        $sha1_d = sha1($msg_key.substr($auth_key, 96 + $x, 32), true);
        $aes_key = substr($sha1_a, 0, 8).substr($sha1_b, 8, 12).substr($sha1_c, 4, 12);
        $aes_iv = substr($sha1_a, 8, 12).substr($sha1_b, 0, 8).substr($sha1_c, 16, 4).substr($sha1_d, 0, 8);

        return [$aes_key, $aes_iv];
    }

    /**
     * @param int $a
     * @param int $b
     *
     * @return float|int
     */
    private function calcRemainder(int $a, int $b)
    {
        $remainder = $a % $b;
        if ($remainder < 0)
            $remainder += abs($b);

        return $remainder;
    }

    /**
     * @param callable $cb function(ResPQ $response)
     *
     * @throws TGException
     */
    private function requestForPQ(callable $cb): void
    {
        $request = new req_pq_multi($this->oldClientNonce);
        $this->socketContainer->getResponseAsync($request, function ($response) use ($cb) {
            $pqResponse = new ResPQ($response);

            if(strcmp($pqResponse->getClientNonce(), $this->oldClientNonce) !== 0) {
                throw new TGException(TGException::ERR_AUTH_INCORRECT_CLIENT_NONCE);
            }
            if(strlen($pqResponse->getServerNonce()) !== 16) {
                throw new TGException(TGException::ERR_AUTH_INCORRECT_SERVER_NONCE);
            }
            $this->obtainedServerNonce = $pqResponse->getServerNonce();
            $cb($pqResponse);
        });
    }

    /**
     * @param PQ       $pq
     * @param ResPQ    $pqData
     * @param callable $cb     function(string)
     * @param bool     $isTemp
     *
     * @throws TGException
     */
    private function requestDHParams(PQ $pq, ResPQ $pqData, callable $cb, bool $isTemp = false)
    {
        // prepare object
        $data = $this->getPqInnerDataMessage($pqData->getPq(), $pq->getP(), $pq->getQ(), $this->oldClientNonce, $pqData->getServerNonce(), $this->newClientNonce, $isTemp);
        $data = $data->toBinary();

        // obtain certificate by fingerprint
        $certificate = $this->getCertificate($pqData->getFingerprints());

        $data_with_hash = sha1($data, true).$data;
        $paddingSize = 255 - strlen($data_with_hash);
        /** @noinspection CryptographicallySecureRandomnessInspection */
        $randomBytes = openssl_random_pseudo_bytes($paddingSize, $strong);
        if ($strong === false || $randomBytes === false) {
            throw new TGException(TGException::ERR_CRYPTO_INVALID);
        }
        $data_with_hash .= $randomBytes;
        $encryptedData = $this->rsa->encrypt($data_with_hash, $certificate->getPublicKey());

        // send object
        $request = new req_dh_params($this->oldClientNonce, $pqData->getServerNonce(), $pq->getP(), $pq->getQ(), $certificate->getFingerPrint(), $encryptedData);
        $this->socketContainer->getResponseAsync($request, function (AnonymousMessage $response) use ($cb) {
            $dhResponse = new DHReq($response);

            if(strcmp($dhResponse->getClientNonce(), $this->oldClientNonce) !== 0) {
                throw new TGException(TGException::ERR_AUTH_INCORRECT_CLIENT_NONCE);
            }
            if(strcmp($dhResponse->getServerNonce(), $this->obtainedServerNonce) !== 0) {
                throw new TGException(TGException::ERR_AUTH_INCORRECT_SERVER_NONCE);
            }
            $cb($dhResponse->getEncryptedAnswer());
        });
    }

    /**
     * @param int[] $receivedFingerPrints
     *
     * @throws TGException
     *
     * @return Certificate
     */
    private function getCertificate(array $receivedFingerPrints): Certificate
    {
        foreach ($receivedFingerPrints as $fingerPrint) {
            $certificate = Certificate::getCertificateByFingerPrint($fingerPrint);
            if ($certificate) {
                Logger::log('Selected fingerprint', $fingerPrint);

                return $certificate;
            }
        }

        throw new TGException(
            TGException::ERR_AUTH_CERT_FINGERPRINT_NOT_FOUND,
            'fingerprints: '.print_r($receivedFingerPrints, true)
        );
    }

    /**
     * @param int $pq
     *
     * @throws TGException
     *
     * @return PQ
     */
    private function findPrimes(int $pq): PQ
    {
        Logger::log('Factorize', $pq);

        return (new GmpFactorizer())->factorize($pq);
    }

    /**
     * @param string $encryptedAnswer
     * @param ResPQ  $pqResponse
     *
     * @throws TGException
     *
     * @return DHServerInnerData
     */
    private function decryptDHResponse(string $encryptedAnswer, ResPQ $pqResponse): DHServerInnerData
    {
        $material1 = $this->newClientNonce.$pqResponse->getServerNonce();
        $material2 = $pqResponse->getServerNonce().$this->newClientNonce;
        $this->tmpAesKey = sha1($material1, true).substr(sha1($material2, true), 0, 12);

        $material3 = $this->newClientNonce.$this->newClientNonce;
        $material4 = $this->newClientNonce;
        $this->tmpAesIV = substr(sha1($material2, true), 12, 8).sha1($material3, true).substr($material4, 0, 4);

        $answer = $this->aes->decryptIgeMode($encryptedAnswer, $this->tmpAesKey, $this->tmpAesIV);

        return $this->createDHInnerDataObject($answer);
    }

    /**
     * @param string $decryptedResponse
     *
     * @throws TGException
     *
     * @return DHServerInnerData
     */
    private function createDHInnerDataObject(string $decryptedResponse): DHServerInnerData
    {
        $messageWithoutHeaders = substr($decryptedResponse, 20, -8);
        $dhInnerData = (new OwnDeserializer())->deserialize($messageWithoutHeaders);

        return new DHServerInnerData($dhInnerData);
    }

    /**
     * @param DHServerInnerData $dhParams
     * @param ResPQ             $pqParams
     * @param callable          $cb       function(AuthParams $params)
     *
     * @throws TGException
     */
    private function setClientDHParams(DHServerInnerData $dhParams, ResPQ $pqParams, callable $cb): void
    {
        /** @noinspection CryptographicallySecureRandomnessInspection */
        $b = openssl_random_pseudo_bytes(256, $strong);
        if ($strong === false || $b === false) {
            throw new TGException(TGException::ERR_CRYPTO_INVALID);
        }
        $g_b = $this->powMod->powMod($dhParams->getG(), $b, $dhParams->getDhPrime());

        $data = new client_dh_inner_data($this->oldClientNonce, $pqParams->getServerNonce(), 0, $g_b);
        $data = $data->toBinary();
        $data_with_hash = sha1($data, true).$data;
        $paddingSize = 16 - strlen($data_with_hash) % 16;
        /** @noinspection CryptographicallySecureRandomnessInspection */
        $randomBytes = openssl_random_pseudo_bytes($paddingSize, $strong);
        if ($strong === false || $randomBytes === false) {
            throw new TGException(TGException::ERR_CRYPTO_INVALID);
        }
        $data_with_hash .= $randomBytes;
        $encrypted_data = $this->aes->encryptIgeMode($data_with_hash, $this->tmpAesKey, $this->tmpAesIV);

        $request = new set_client_dh_params($this->oldClientNonce, $pqParams->getServerNonce(), $encrypted_data);
        $this->socketContainer->getResponseAsync($request, function ($response) use ($cb, $dhParams, $b) {
            $dh_params_answer = new DHGenOk($response);

            if(strcmp($dh_params_answer->getClientNonce(), $this->oldClientNonce) !== 0) {
                throw new TGException(TGException::ERR_AUTH_INCORRECT_CLIENT_NONCE);
            }
            if(strcmp($dh_params_answer->getServerNonce(), $this->obtainedServerNonce) !== 0) {
                throw new TGException(TGException::ERR_AUTH_INCORRECT_SERVER_NONCE);
            }
            $initialServerSalt = substr($this->newClientNonce, 0, 8) ^ substr($this->obtainedServerNonce, 0, 8);
            $authKey = $this->powMod->powMod($dhParams->getGA(), $b, $dhParams->getDhPrime());

            if(strlen($authKey) !== 256) {
                throw new TGException(TGException::ERR_AUTH_KEY_BAD_LENGTH, bin2hex($authKey));
            }
            if(strlen($initialServerSalt) !== 8) {
                throw new TGException(TGException::ERR_AUTH_SALT_BAD_LENGTH, bin2hex($initialServerSalt));
            }
            $cb(new AuthParams($authKey, $initialServerSalt));
        });
    }

    /**
     * @throws TGException
     */
    public function poll(): void
    {
        /** @noinspection UnusedFunctionResultInspection */
        $this->socketContainer->readMessage();
    }
}
