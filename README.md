# Install & Use

```
curl -L https://npc.nos-eastchina1.126.net/dl/jwks2pem.tar.gz | tar -zxC /usr/local/bin

curl -sSL https://www.googleapis.com/oauth2/v3/certs | jwks2pem

jwks2pem <<<'{
 "keys": [
  {
   "kty": "RSA",
   "alg": "RS256",
   "use": "sig",
   "kid": "affc62907a446182adc1fa4e81fdba6310dce63f",
   "n": "iQM7pTQvWzrvxF9DXghTjZJ0aYq-scEwQrdhT6OHtQGP25okbLH0W-H4XiNnbBTDAyiHhStB2z_bj-2tt60P9ePxdTSMnax87-55xsEZRF66Q9Vu56JJOMRBO-ze_vd_nMIF1qo0MDZl-89wZDsGnplai1e3swvqVo3mS8E3Z6BIlh8BMQTv_BHavY6tCQ1tczlFE3DfSSEu5DnP7dPKA2c2u0ljuDRcR33nr14fpUsiVUU4q__J76-R2HvKpdMB8SQZFz5lDQzivZNQvNmHnD1VAMtFcLkQTXJ0PuNIhMw3MBMbaiOW2enoEUGRj8Q5Y-UuWRvuMocYdzxVoNiA6w",
   "e": "AQAB"
  },
  {
   "kty": "RSA",
   "alg": "RS256",
   "use": "sig",
   "kid": "3f3ef9c7803cd0b8d75247ee0d31fdd5c2cf3812",
   "n": "xM3ZHCgrJLe8y0rBZUWHOS1pCpJ2PjM_gw0WI9D0rljoZ7zWQpEC5UwpWaJqqDKxokt-kKP9GYXILqEsZrQ86qXvRZDPrP39RUjMl3Yl0hE4PlTx3aXuSE8SYqy506yduKjHw3seQHBiqSkVdLXSXqsEKUUrtFEgUxwL5L0yU4N3uJcAWK-oka8RxQSFJEilX5UOH-Qmz4UEeIr7Ma8cdsjibUc6xC9SRJtblmAdDDA_-1aMAJuYH8tGYnpTftwKbaaD0btq0LIzrsFnLu2--jaBul4u0k0jukolnUP0XSqE6NEc0iHTCdbKHZN6LrKVZoUqncTAS7Qa6TbgN1-lHw",
   "e": "AQAB"
  }
 ]
}'

jwks2pem <<<'{
   "kty": "RSA",
   "alg": "RS256",
   "use": "sig",
   "kid": "affc62907a446182adc1fa4e81fdba6310dce63f",
   "n": "iQM7pTQvWzrvxF9DXghTjZJ0aYq-scEwQrdhT6OHtQGP25okbLH0W-H4XiNnbBTDAyiHhStB2z_bj-2tt60P9ePxdTSMnax87-55xsEZRF66Q9Vu56JJOMRBO-ze_vd_nMIF1qo0MDZl-89wZDsGnplai1e3swvqVo3mS8E3Z6BIlh8BMQTv_BHavY6tCQ1tczlFE3DfSSEu5DnP7dPKA2c2u0ljuDRcR33nr14fpUsiVUU4q__J76-R2HvKpdMB8SQZFz5lDQzivZNQvNmHnD1VAMtFcLkQTXJ0PuNIhMw3MBMbaiOW2enoEUGRj8Q5Y-UuWRvuMocYdzxVoNiA6w",
   "e": "AQAB"
  }'

```