<?php

namespace TelegramOSINT\Auth;

interface Authorization
{
    /**
     * @param callable $onAuthKeyReady function(AuthKey $authKey)
     * @param bool     $forRegister
     */
    public function createAuthKey(callable $onAuthKeyReady, bool $forRegister = false);

    public function poll(): void;
}
