<?php

namespace TelegramOSINT\TGConnection\SocketMessenger;

use LogicException;
use TelegramOSINT\Exception\TGException;
use TelegramOSINT\LibConfig;
use TelegramOSINT\Logger\ClientDebugLogger;
use TelegramOSINT\Logger\Logger;
use TelegramOSINT\MTSerialization\AnonymousMessage;
use TelegramOSINT\MTSerialization\MTDeserializer;
use TelegramOSINT\MTSerialization\OwnImplementation\OwnDeserializer;
use TelegramOSINT\TGConnection\DataCentre;
use TelegramOSINT\TGConnection\Socket\Socket;
use TelegramOSINT\TGConnection\SocketMessenger\MessengerTools\MessageIdGenerator;
use TelegramOSINT\TGConnection\SocketMessenger\MessengerTools\OuterHeaderWrapper;
use TelegramOSINT\TLMessage\TLMessage\ClientMessages\get_config;
use TelegramOSINT\TLMessage\TLMessage\ServerMessages\DcConfigApp;
use TelegramOSINT\TLMessage\TLMessage\TLClientMessage;

class NotEncryptedSocketMessenger extends TgSocketMessenger
{
    /**
     * @var OuterHeaderWrapper
     */
    private $outerHeaderWrapper;
    /**
     * @var MessageIdGenerator
     */
    private $msgIdGenerator;
    /**
     * @var MTDeserializer
     */
    private $deserializer;
    /** @var ClientDebugLogger|null */
    private $logger;
    /** @var AnonymousMessage|null */
    private $config;
    private $callbackQueue = [];
    private $writeQueue = [];
    /**
     * pre-generated message id (used for auth flow)
     *
     * @var int|null
     */
    private $messageId;

    /**
     * @param Socket                 $socket
     * @param ClientDebugLogger|null $logger
     */
    public function __construct(Socket $socket, ?ClientDebugLogger $logger = null)
    {
        parent::__construct($socket);
        $this->outerHeaderWrapper = new OuterHeaderWrapper();
        $this->msgIdGenerator = new MessageIdGenerator();
        $this->deserializer = new OwnDeserializer();
        $this->logger = $logger;
    }

    private function log(string $code, string $message): void
    {
        if ($this->logger) {
            $this->logger->debugLibLog($code, $message);
        } else {
            Logger::log($code, $message);
        }
    }

    /**
     * @throws TGException
     *
     * @return AnonymousMessage
     */
    public function readMessage(): ?AnonymousMessage
    {
        if (!$this->socket->ready()) {
            $this->socket->poll();

            return null;
        }
        if ($this->writeQueue) {
            foreach ($this->writeQueue as $item) {
                $this->writeMessage($item);
            }
            $this->writeQueue = [];
        }
        $packet = $this->readPacket();
        if (!$packet) {
            if ($this->callbackQueue) {
                $firstIndex = array_key_first($this->callbackQueue);
                [, $lastTime] = $this->callbackQueue[$firstIndex];
                if (microtime(true) - $lastTime > LibConfig::CONN_SOCKET_TIMEOUT_WAIT_RESPONSE_MS) {
                    throw new TGException(TGException::ERR_MSG_RESPONSE_TIMEOUT);
                }
            }

            return null;
        }

        $this->log('Read_Message_Binary', bin2hex($packet));

        $decoded = $this->decodePayload($this->outerHeaderWrapper->unwrap($packet));
        $deserialized = $this->deserializer->deserialize($decoded);

        $this->log('Read_Message_Binary', bin2hex($decoded));
        $this->log('Read_Message_TL', $deserialized->getDebugPrintable());

        if ($this->callbackQueue) {
            [$callback,] = array_shift($this->callbackQueue);
            $callback($deserialized);
        }

        return $deserialized;
    }

    /**
     * @param string $payload
     *
     * @throws TGException
     *
     * @return false|string
     */
    private function decodePayload($payload)
    {
        $auth_key_id = unpack('V', substr($payload, 0, 8))[1];

        // must be 0 because it is unencrypted messaging
        if($auth_key_id !== 0) {
            throw new TGException(TGException::ERR_TL_CONTAINER_BAD_AUTHKEY_ID_MUST_BE_0);
        }
        $message_data_length = unpack('V', substr($payload, 16, 4))[1];

        return substr($payload, 20, $message_data_length);
    }

    /**
     * @throws TGException
     *
     * @return int
     */
    public function getMessageId(): int
    {
        if ($this->messageId) {
            throw new TGException(TGException::ERR_ASSERT_MESSAGE_ID_GET_ONCE);
        }
        $this->messageId = $this->msgIdGenerator->generateNext();

        return $this->messageId;
    }

    /**
     * @param TLClientMessage $payload
     *
     * @throws TGException
     */
    public function writeMessage(TLClientMessage $payload): void
    {
        $payloadStr = $this->outerHeaderWrapper->wrap(
            $this->wrapPayloadWithMessageId($payload->toBinary())
        );

        $this->socket->writeBinary($payloadStr);

        $this->log('Write_Message_Binary', bin2hex($payload->toBinary()));
        $this->log('Write_Message_TL', $this->deserializer->deserialize($payload->toBinary())->getDebugPrintable());
    }

    /**
     * @param string $payload
     *
     * @return string
     */
    private function wrapPayloadWithMessageId(string $payload): string
    {
        $msg_id = $this->messageId !== null
            ? $this->messageId
            : $this->msgIdGenerator->generateNext();
        $this->messageId = null;
        $length = strlen($payload);
        $payload = pack('x8PI', $msg_id, $length).$payload;

        return $payload;
    }

    /**
     * @return DataCentre
     */
    public function getDCInfo(): DataCentre
    {
        return $this->socket->getDCInfo();
    }

    public function terminate(): void
    {
        $this->socket->terminate();
    }

    /**
     * @param TLClientMessage $message
     * @param callable        $cb      function(AnonymousMessage $message)
     *
     * @throws TGException
     */
    public function getResponseAsync(TLClientMessage $message, callable $cb): void
    {
        $callback = $cb;
        if ($message instanceof get_config) {
            if ($this->config) {
                $cb($this->config);

                return;
            }
            $callback = function (AnonymousMessage $message) use ($cb) {
                $this->config = $message;
                $cb($message);
            };
        }
        $this->callbackQueue[] = [$callback, microtime(true)];
        // Dummy impl
        if ($this->socket->ready()) {
            $this->writeMessage($message);
        } else {
            $this->writeQueue[] = $message;
        }
    }

    /**
     * @param array    $messages
     * @param callable $onLastResponse
     *
     * @throws LogicException
     */
    public function getResponseConsecutive(array $messages, callable $onLastResponse): void
    {
        throw new LogicException('Not implemented and not used');
    }

    /**
     * @throws TGException
     *
     * @return DcConfigApp|null
     */
    public function getDCConfig(): ?DcConfigApp
    {
        if ($this->config) {
            return new DcConfigApp($this->config);
        }

        return null;
    }
}
