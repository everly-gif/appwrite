<?php

namespace Appwrite\Auth\OAuth2;

use Appwrite\Auth\OAuth2;

// Reference Material
// https://developer.adobe.com/developer-console/docs/guides/authentication/OAuth/

class Adobe extends OAuth2
{
    private string $endpoint = 'https://ims-na1.adobelogin.com/';
    protected array $user = [];
    protected array $tokens = [];
    protected array $scopes = [
        'openid',
        'profile',
        'email'
    ];

    public function getName(): string
    {
        return 'adobe';
    }

    public function getLoginURL(): string
    {
        $url = $this->endpoint . '' . \http_build_query([
            'client_id' => $this->appID,
            'redirect_uri' => $this->callback,
            'scope' => \implode(' ', $this->getScopes()),
            'state' => \json_encode($this->state),
            'response_type' => 'code',
        ]);

        return $url;
    }

    protected function getTokens(string $code): array
    {
        if (empty($this->tokens)) {
            $headers = ['Authorization: Basic ' . \base64_encode($this->appID . ':' . $this->appSecret), 'Content-Type: application/x-www-form-urlencoded'];
            $this->tokens = \json_decode($this->request(
                'POST',
                $this->endpoint . '/ims/token/v3',
                $headers,
                \http_build_query([
                    'code' => $code,
                    'grant_type' => 'authorization_code',
                ])
            ), true);
        }

        return $this->tokens;
    }

    public function refreshTokens(string $refreshToken): array
    {
        $headers = ['Authorization: Basic ' . \base64_encode($this->appID . ':' . $this->appSecret), 'Content-Type: application/x-www-form-urlencoded'];
        $this->tokens = \json_decode($this->request(
            'POST',
            $this->endpoint . 'ims/token/v3',
            $headers,
            \http_build_query([
                'grant_type' => 'refresh_token',
                'refresh_token' => $refreshToken,
            ])
        ), true);

        if (empty($this->tokens['refresh_token'])) {
            $this->tokens['refresh_token'] = $refreshToken;
        }

        return $this->tokens;
    }

    public function getUserID(string $accessToken): string
    {
        $user = $this->getUser($accessToken);

        $userId = $user["sub"] ?? '';

        return $userId;
    }

    public function getUserEmail(string $accessToken): string
    {
        $user = $this->getUser($accessToken);

        $userEmail = $user["email"] ?? '';

        return $userEmail;
    }

    public function isEmailVerified(string $accessToken): bool
    {
        $user = $this->getUser($accessToken);

        $isVerified = $user["email_verified"] ?? '';

        return $isVerified;
    }

    public function getUserName(string $accessToken): string
    {
        $user = $this->getUser($accessToken);

        // TODO: Pick username from $user response
        $username = $user["name"] ?? '';

        return $username;
    }

    protected function getUser(string $accessToken): array
    {
        $headers = [
            'Authorization: Bearer ' . \urlencode($accessToken)
        ];

        if (empty($this->user)) {
            $this->user = \json_decode($this->request('GET', 'https://ims-na1.adobelogin.com/ims/userinfo/v2?client_id=' . $this->appID, $headers), true);
        }


        return $this->user;
    }
}
